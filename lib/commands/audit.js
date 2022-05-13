const Arborist = require('@npmcli/arborist')
const auditReport = require('npm-audit-report')
const chalk = require('chalk')
const crypto = require('crypto')
const fetch = require('npm-registry-fetch')
const localeCompare = require('@isaacs/string-locale-compare')('en')
const npa = require('npm-package-arg')
const pacote = require('pacote')

const ArboristWorkspaceCmd = require('../arborist-cmd.js')
const auditError = require('../utils/audit-error.js')
const {
  registry: { default: defaultRegistry },
} = require('../utils/config/definitions.js')
const log = require('../utils/log-shim.js')
const pulseTillDone = require('../utils/pulse-till-done.js')
const reifyFinish = require('../utils/reify-finish.js')

const verifySignature = async ({ message, signature, publicKey }) => {
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
    this.keys = new Map()
    this.invalid = new Set()
    this.missing = new Set()
    this.audited = 0
    this.verified = 0
    this.output = []
    this.exitCode = 0
  }

  async run () {
    const start = process.hrtime.bigint()

    // Find all deps in tree
    this.edges = this.getEdgesOut(this.tree.inventory.values(), this.filterSet)
    if (this.edges.size === 0) {
      throw new Error('No dependencies found in current install')
    }

    // Prefetch and cache public keys from used registries
    const registries = this.findAllRegistryUrls(this.edges, this.npm.flatOptions)
    for (const registry of registries) {
      const keys = await this.getKeys({ registry })
      if (keys) {
        this.keys.set(registry, keys)
      }
    }

    await Promise.all([...this.edges].map((edge) => this.getVerifiedInfo(edge)))

    // TODO: Check this case
    if (!this.audited) {
      throw new Error('No dependencies found in current install')
    }

    // Sort alphabetically
    const invalid = Array.from(this.invalid).sort((a, b) => localeCompare(a.name, b.name))
    const missing = Array.from(this.missing).sort((a, b) => localeCompare(a.name, b.name))

    const verified = invalid.length === 0 && missing.length === 0

    if (!verified) {
      this.exitCode = 1
    }

    const end = process.hrtime.bigint()
    const elapsed = end - start

    if (this.npm.config.get('json')) {
      this.appendOutput(this.makeJSON({ invalid, missing }))
    } else {
      const timing = `audited ${this.audited} packages in ${Math.floor(Number(elapsed) / 1e9)}s`
      const verifiedPrefix = verified ? 'verified registry signatures, ' : ''
      this.appendOutput(`${verifiedPrefix}${timing}\n`)

      if (this.verified && !verified) {
        this.appendOutput(
          `${this.verified} packages have ${this.npm.color ? chalk.bold('verified') : 'verified'}` +
          ` registry signatures\n`
        )
      }

      if (missing.length) {
        const msg = missing.length === 1 ?
          `package has a ${this.npm.color ? chalk.bold(chalk.magenta('missing')) : 'missing'}` +
          ` registry signature` :
          `packages have ${this.npm.color ? chalk.bold(chalk.magenta('missing')) : 'missing'}` +
          ` registry signatures`
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
          `package has an ${this.npm.color ? chalk.bold(chalk.red('invalid')) : 'invalid'}` +
          ` registry signature` :
          `packages have ${this.npm.color ? chalk.bold(chalk.red('invalid')) : 'invalid'}` +
          ` registry signatures`
        this.appendOutput(
          `${missing.length ? '\n' : ''}${invalid.length} ${msg}:\n`
        )
        this.appendOutput(this.humanOutput(invalid))
        const plural = invalid.length === 1 ? '' : 's'
        this.appendOutput(
          `\nSomeone might have tampered with the package${plural} ` +
          `since it was published on the registry (monster-in-the-middle attack)!\n`
        )
      }
    }
  }

  findAllRegistryUrls (edges, opts) {
    return new Set(Array.from(edges, (edge) => {
      let alias = false
      try {
        alias = npa(edge.spec).subSpec
      } catch (err) {
      }
      const spec = npa(alias ? alias.name : edge.name)
      return fetch.pickRegistry(spec, opts)
    }))
  }

  appendOutput (...args) {
    this.output.push(...args.flat())
  }

  report () {
    return { report: this.output.join('\n'), exitCode: this.exitCode }
  }

  getEdgesOut (nodes, filterSet) {
    const edges = new Set()
    for (const node of nodes) {
      for (const edge of node.edgesOut.values()) {
        const filteredOut =
          edge.from
            && filterSet
            && filterSet.size > 0
            && !filterSet.has(edge.from.target)

        if (!filteredOut) {
          edges.add(edge)
        }
      }
    }
    return edges
  }

  async getKeys ({ registry }) {
    return await fetch.json('/-/npm/v1/keys', {
      ...this.npm.flatOptions,
      registry,
    }).then(({ keys }) => keys.map((key) => ({
      ...key,
      pemkey: `-----BEGIN PUBLIC KEY-----\n${key.key}\n-----END PUBLIC KEY-----`,
    }))).catch(err => {
      if (err.code === 'E404') {
        return null
      } else {
        throw err
      }
    })
  }

  async getVerifiedInfo (edge) {
    let alias = false
    try {
      alias = npa(edge.spec).subSpec
    } catch (err) {
    }
    const spec = npa(alias ? alias.name : edge.name)
    const node = edge.to || edge
    const { location } = node
    const { version } = node.package || {}

    const type = edge.optional ? 'optionalDependencies'
      : edge.bundled ? 'bundledDependencies'
      : edge.peer ? 'peerDependencies'
      : edge.dev ? 'devDependencies'
      : 'dependencies'

    // Skip potentially optional packages that are not on disk, as these could
    // be omitted during install
    if (edge.error === 'MISSING' && type !== 'dependencies') {
      return
    }

    // Skip packages that don't have a installed version, e.g. optonal dependencies
    if (!version) {
      return
    }

    for (const omitType of this.npm.config.get('omit')) {
      if (node[omitType]) {
        return
      }
    }

    // Skip if the package is not in a registry, e.g. git or local workspace package
    try {
      if (!npa(`${edge.name}@${edge.spec}`).registry) {
        return null
      }
    } catch (err) {
      return null
    }

    this.audited += 1
    const name = alias ? edge.spec.replace('npm', edge.name) : edge.name
    const registry = fetch.pickRegistry(spec, this.npm.flatOptions)
    const manifest = await pacote.manifest(`${name}@${version}`, this.npm.flatOptions)
    const { _integrity: integrity, _signatures, _resolved: resolved } = manifest
    const message = `${name}@${version}:${integrity}`
    const signatures = _signatures || []

    const keys = this.keys.get(registry) || []
    const validKeys = keys.filter((publicKey) => {
      if (!publicKey.expires) {
        return true
      }
      return Date.parse(publicKey.expires) > Date.now()
    })

    // Currently we only care about missing signatures on registries that provide a public key
    // We could make this configurable in the future with a strict/paranoid mode
    if (!signatures.length && validKeys.length) {
      this.missing.add({
        name,
        version,
        location,
        resolved,
        integrity,
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
          `but no corresponding public key can be found on ${registry}-/npm/v1/keys`
        )
      } else if (publicKey && !validPublicKey) {
        throw new Error(
          `${name} has a signature with keyid: ${signature.keyid} ` +
          `but the corresponding public key on ${registry}-/npm/v1/keys has expired ` +
          `(${publicKey.expires})`
        )
      }

      const valid = await verifySignature({
        message,
        signature: signature.sig,
        publicKey: validPublicKey.pemkey,
      })

      if (!valid) {
        this.invalid.add({
          name,
          type,
          version,
          resolved,
          location,
          integrity,
          registry,
          signature: signature.sig,
          keyid: signature.keyid,
        })
      } else {
        this.verified += 1
      }
    }))
  }

  humanOutput (list) {
    const uniquePackages = Array.from(list.reduce((set, v) => {
      let nameVersion = `${v.name}@${v.version}`
      if (this.npm.color) {
        nameVersion = chalk.red(nameVersion)
      }
      const registry = v.registry
      const suffix = registry !== defaultRegistry ? ` (${registry})` : ''
      set.add(`${nameVersion}${suffix}`)
      return set
    }, new Set()))

    return uniquePackages.join('\n')
  }

  makeJSON ({ invalid, missing }) {
    const out = {}
    invalid.forEach(dep => {
      const {
        version,
        location,
        resolved,
        integrity,
        signature,
        keyid,
      } = dep
      out.invalid = out.invalid || {}
      out.invalid[location] = {
        version,
        resolved,
        integrity,
        signature,
        keyid,
      }
    })
    missing.forEach(dep => {
      const {
        version,
        location,
        resolved,
        integrity,
      } = dep
      out.missing = out.missing || {}
      out.missing[location] = {
        version,
        resolved,
        integrity,
      }
    })
    return JSON.stringify(out, null, 2)
  }
}

class Audit extends ArboristWorkspaceCmd {
  static description = 'Run a security audit'
  static name = 'audit'
  static params = [
    'audit-level',
    'dry-run',
    'force',
    'json',
    'package-lock-only',
    'omit',
    'foreground-scripts',
    'ignore-scripts',
    ...super.params,
  ]

  static usage = ['[fix]']

  async completion (opts) {
    const argv = opts.conf.argv.remain

    if (argv.length === 2) {
      return ['fix']
    }

    switch (argv[2]) {
      case 'fix':
        return []
      default:
        throw new Error(argv[2] + ' not recognized')
    }
  }

  async exec (args) {
    if (args[0] === 'signatures') {
      await this.auditSignatures()
    } else {
      await this.auditAdvisories(args)
    }
  }

  async auditAdvisories (args) {
    const reporter = this.npm.config.get('json') ? 'json' : 'detail'
    const opts = {
      ...this.npm.flatOptions,
      audit: true,
      path: this.npm.prefix,
      reporter,
      workspaces: this.workspaceNames,
    }

    const arb = new Arborist(opts)
    const fix = args[0] === 'fix'
    await arb.audit({ fix })
    if (fix) {
      await reifyFinish(this.npm, arb)
    } else {
      // will throw if there's an error, because this is an audit command
      auditError(this.npm, arb.auditReport)
      const result = auditReport(arb.auditReport, opts)
      process.exitCode = process.exitCode || result.exitCode
      this.npm.output(result.report)
    }
  }

  async auditSignatures () {
    log.newItem('loading intalled packages')
    const reporter = this.npm.config.get('json') ? 'json' : 'detail'
    const opts = {
      ...this.npm.flatOptions,
      path: this.npm.prefix,
      reporter,
      workspaces: this.workspaceNames,
    }

    const arb = new Arborist(opts)
    const tree = await arb.loadActual()
    let filterSet = new Set()
    if (opts.workspaces && opts.workspaces.length) {
      filterSet =
        arb.workspaceDependencySet(
          tree,
          opts.workspaces,
          this.npm.flatOptions.includeWorkspaceRoot
        )
    } else if (!this.npm.flatOptions.workspacesEnabled) {
      filterSet =
        arb.excludeWorkspacesDependencySet(tree)
    }

    log.newItem('verifying registry signatures')
    const verify = new VerifySignatures(tree, filterSet, this.npm, { ...opts })
    await pulseTillDone.withPromise(verify.run())
    const result = verify.report()
    process.exitCode = process.exitCode || result.exitCode
    this.npm.output(result.report)
  }
}

module.exports = Audit
