const cacache = require('cacache')
const chalk = require('chalk')
const crypto = require('crypto')
const fetch = require('npm-registry-fetch')
const jsonParse = require('json-parse-even-better-errors')
const localeCompare = require('@isaacs/string-locale-compare')('en')
const npa = require('npm-package-arg')
const pacote = require('pacote')
const path = require('path')
const pickManifest = require('npm-pick-manifest')
const table = require('text-table')

const ansiTrim = require('../utils/ansi-trim.js')

const validateSignature = async ({ message, signature, publicKey }) => {
  const verifier = crypto.createVerify('SHA256')
  verifier.write(message)
  verifier.end()
  return verifier.verify(publicKey, signature, 'base64')
}

class VerifySignatures {
  constructor (tree, filterSet, npm, opts) {
    this.tree = tree
    this.filterSet = filterSet
    this.npm = npm
    this.opts = opts
    this.edges = new Set()
    this.keys = new Map()
    this.invalid = new Set()
    this.missing = new Set()
    this.verified = 0
    this.output = []
    this.exitCode = 0
  }

  async run () {
    // Find all deps in tree
    const nodes = this.tree.inventory.values()
    this.getEdges(nodes, 'edgesOut')

    const edges = Array.from(this.edges)
    const start = process.hrtime.bigint()
    const registries = this.findAllRegistryUrls(edges, this.npm.flatOptions)

    // Prefetch and cache public keys from the used registries
    await Promise.all(registries.map(async (registry) => this.getKeys({ registry })))
    await Promise.all(edges.map(async (edge) => await this.getVerifiedInfo(edge)))

    const end = process.hrtime.bigint()
    const elapsed = end - start

    // sort alphabetically
    const invalid = Array.from(this.invalid).sort((a, b) => localeCompare(a.name, b.name))
    const missing = Array.from(this.missing).sort((a, b) => localeCompare(a.name, b.name))

    const verified = invalid.length === 0 && missing.length === 0

    if (!verified) {
      this.exitCode = 1
    }

    if (this.npm.config.get('json')) {
      this.appendOutput(this.makeJSON({ invalid, missing }))
    } else {
      const timing = `audited ${edges.length} packages in ${Math.floor(Number(elapsed) / 1e9)}s`
      const verifiedPrefix = verified ? 'verified signatures, ' : ''
      this.appendOutput(`${verifiedPrefix}${timing}\n`)

      if (missing.length) {
        const msg = missing.length === 1 ?
          `package has a ${chalk.bold(chalk.magenta('missing'))} registry signature` :
          `packages have ${chalk.bold(chalk.magenta('missing'))} registry signatures`
        this.appendOutput(
          `${missing.length} ${msg} but the registry is ` +
          `providing signing keys${this.npm.config.get('missing') ? ':\n' : ''}`
        )
        // TODO: This might not be the right option for this
        if (this.npm.config.get('missing')) {
          this.appendOutput(this.humanOutput(missing))
        } else {
          this.appendOutput(`  run \`npm audit signatures --missing\` for details`)
        }
      }

      if (invalid.length) {
        const msg = invalid.length === 1 ?
          `package has an ${chalk.bold(chalk.red('invalid'))} registry signature` :
          `packages have ${chalk.bold(chalk.red('invalid'))} registry signatures`
        this.appendOutput(
          `${missing.length ? '\n' : ''}${invalid.length} ${msg}:\n`
        )
        this.appendOutput(this.humanOutput(invalid))
        const plural = invalid.length === 1 ? '' : 's'
        this.appendOutput(
          `\nSomeone might have tampered with the package${plural} ` +
          `since being published on the registry (monster-in-the-middle attack)!\n`
        )
      }
    }
  }

  findAllRegistryUrls (edges, opts) {
    return Array.from(edges.reduce((p, edge) => {
      let alias = false
      try {
        alias = npa(edge.spec).subSpec
      } catch (err) {
      }
      const spec = npa(alias ? alias.name : edge.name)
      p.add(fetch.pickRegistry(spec, opts))
      return p
    }, new Set()))
  }

  appendOutput (...args) {
    args = [...args].flat()
    for (const arg of args) {
      this.output.push(arg)
    }
  }

  report () {
    return { report: this.output.join('\n'), exitCode: this.exitCode }
  }

  getEdges (nodes, type) {
    // when no nodes are provided then it should only read direct deps
    // from the root node and its workspaces direct dependencies
    if (!nodes) {
      this.getEdgesOut(this.tree)
      this.getWorkspacesEdges()
      return
    }

    for (const node of nodes) {
      type === 'edgesOut'
        ? this.getEdgesOut(node)
        : this.getEdgesIn(node)
    }
  }

  getEdgesIn (node) {
    for (const edge of node.edgesIn) {
      this.trackEdge(edge)
    }
  }

  getEdgesOut (node) {
    // TODO: normalize usage of edges and avoid looping through nodes here
    if (this.npm.config.get('global')) {
      for (const child of node.children.values()) {
        this.trackEdge(child)
      }
    } else {
      for (const edge of node.edgesOut.values()) {
        this.trackEdge(edge)
      }
    }
  }

  trackEdge (edge) {
    const filteredOut =
      edge.from
        && this.filterSet
        && this.filterSet.size > 0
        && !this.filterSet.has(edge.from.target)

    if (filteredOut) {
      return
    }

    this.edges.add(edge)
  }

  getWorkspacesEdges (node) {
    if (this.npm.config.get('global')) {
      return
    }

    for (const edge of this.tree.edgesOut.values()) {
      const workspace = edge
        && edge.to
        && edge.to.target
        && edge.to.target.isWorkspace

      if (workspace) {
        this.getEdgesOut(edge.to.target)
      }
    }
  }

  async getPackument (spec) {
    const packument = await pacote.packument(spec, {
      ...this.npm.flatOptions,
      fullMetadata: this.npm.config.get('long'),
      preferOffline: true,
    })
    return packument
  }

  async getKeys ({ registry }) {
    const cachePath = path.join(this.npm.cache, '_cacache')
    const cachedKey = `${registry}-/npm/v1/keys`

    try {
      const entry = await cacache.get(cachePath, cachedKey)
      const cache = jsonParse(entry.data)
      if (cache.expires && Date.now() > Date.parse(cache.expires)) {
        await cacache.rm.entry(cachePath, cachedKey)
        throw new Error('Cache expired')
      } else {
        return cache.keys
      }
    } catch {
      const keys = await fetch.json('/-/npm/v1/keys', {
        ...this.npm.flatOptions,
        registry,
      }).then(({ keys }) => keys.map((key) => {
        key.pemKey = `-----BEGIN PUBLIC KEY-----\n${key.key}\n-----END PUBLIC KEY-----`
        return key
      })).catch(err => {
        if (err.code === 'E404') {
          return null
        } else {
          throw err
        }
      })
      const inOneWeekMs = 1000 * 60 * 60 * 24 * 7
      const cache = {
        expires: new Date(Date.now() + inOneWeekMs).toISOString(),
        keys,
      }
      await cacache.put(cachePath, cachedKey, JSON.stringify(cache))
      return keys
    }
  }

  async getVerifiedInfo (edge) {
    let alias = false
    try {
      alias = npa(edge.spec).subSpec
    } catch (err) {
    }
    const spec = npa(alias ? alias.name : edge.name)
    const node = edge.to || edge
    const { path, location } = node
    const { version } = node.package || {}
    if (!version) {
      return
    }
    const type = edge.optional ? 'optionalDependencies'
      : edge.peer ? 'peerDependencies'
      : edge.dev ? 'devDependencies'
      : 'dependencies'

    for (const omitType of this.npm.config.get('omit')) {
      if (node[omitType]) {
        return
      }
    }

    // deps different from prod not currently
    // on disk are not included in the output
    if (edge.error === 'MISSING' && type !== 'dependencies') {
      return
    }

    try {
      const packument = await this.getPackument(spec)
      // if it's not a range, version, or tag, skip it
      try {
        if (!npa(`${edge.name}@${edge.spec}`).registry) {
          return null
        }
      } catch (err) {
        return null
      }

      const name = alias ? edge.spec.replace('npm', edge.name) : edge.name
      const { homepage } = packument

      const registry = fetch.pickRegistry(spec, this.npm.flatOptions)

      const versionPackument = pickManifest(packument, version, this.npm.flatOptions)
      const versionCreated = packument.time && packument.time[version]
      const dist = versionPackument.dist || {}
      const { integrity } = dist
      const message = `${name}@${version}:${integrity}`
      const signatures = dist.signatures || []
      const keys = (await this.getKeys({ registry })) || []
      const validKeys = keys.filter((publicKey) => {
        if (!publicKey.expires) {
          return true
        }
        return Date.parse(versionCreated) < Date.parse(publicKey.expires)
      })

      // Currently we only care about missing signatures on registries that provide a public key
      // Note: we could make this configurable in the future with a strict/paranoid mode
      if (!signatures.length && validKeys.length) {
        this.missing.add({
          name,
          path,
          version,
          location,
          homepage,
          registry,
        })

        return
      }

      await Promise.all(signatures.map(async (signature) => {
        const publicKey = keys.filter(key => key.keyid === signature.keyid)[0]
        const validPublicKey = validKeys.filter(key => key.keyid === signature.keyid)[0]

        if (!publicKey && !validPublicKey) {
          throw new Error(
            `${name} has a signature with keyid: ${signature.keyid} ` +
            `but not corresponding public key can be found on ${registry}-/npm/v1/keys`
          )
        } else if (publicKey && !validPublicKey) {
          throw new Error(
            `${name} has a signature with keyid: ${signature.keyid} ` +
            `but the corresponding public key on ${registry}-/npm/v1/keys has expired ` +
            `(${publicKey.expires})`
          )
        }

        const valid = await validateSignature({
          message,
          signature: signature.sig,
          publicKey: validPublicKey.pemKey,
        })

        if (!valid) {
          this.invalid.add({
            name,
            path,
            type,
            version,
            location,
            homepage,
            registry,
            integrity,
            signature: signature.sig,
            keyid: signature.keyid,
          })
        } else {
          this.verified++
        }
      }))
    } catch (err) {
      // silently catch and ignore ETARGET, E403 &
      // E404 errors, deps are just skipped
      if (!(
        err.code === 'ETARGET' ||
        err.code === 'E403' ||
        err.code === 'E404')
      ) {
        throw err
      }
    }
  }

  humanOutput (list) {
    const invalidList = list.map(x => this.makePretty(x))
    const outHead = ['Package',
      'Version',
      'Location',
      'Registry',
    ]

    if (this.npm.config.get('long')) {
      outHead[4] = 'Homepage'
    }

    const outTable = [outHead].concat(invalidList)

    if (this.npm.color) {
      outTable[0] = outTable[0].map(heading => chalk.underline(heading))
    }

    const tableOpts = {
      align: ['l', 'r', 'r', 'r', 'l'],
      stringLength: s => ansiTrim(s).length,
    }

    return table(outTable, tableOpts)
  }

  // formatting functions
  makePretty (dep) {
    const {
      version = 'MISSING',
      homepage = '',
      name,
      location,
      registry,
    } = dep

    const columns = [name, version, location, registry]

    if (this.npm.config.get('long')) {
      columns[4] = homepage
    }

    if (this.npm.color) {
      columns[0] = chalk.red(columns[0])
    }

    return columns
  }

  makeJSON ({ invalid, missing }) {
    const out = {}
    invalid.forEach(dep => {
      const {
        name,
        version,
        path,
        registry,
        integrity,
        signature,
        keyid,
        homepage,
      } = dep
      out.invalid ||= {}
      out.invalid[name] = {
        version,
        location: path,
        registry,
        signature,
        integrity,
        keyid,
        homepage,
      }
    })
    missing.forEach(dep => {
      const {
        name,
        version,
        path,
        registry,
        homepage,
      } = dep
      out.missing ||= {}
      out.missing[name] = {
        version,
        location: path,
        registry,
        homepage,
      }
    })
    return JSON.stringify(out, null, 2)
  }
}

module.exports = VerifySignatures
