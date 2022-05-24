const Arborist = require('@npmcli/arborist')
const auditReport = require('npm-audit-report')
const chalk = require('chalk')
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

const sortAlphabetically = (a, b) => localeCompare(a.name, b.name)

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
    const registries = this.findAllRegistryUrls(this.edges)
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

    const invalid = Array.from(this.invalid).sort(sortAlphabetically)
    const missing = Array.from(this.missing).sort(sortAlphabetically)

    const verified = invalid.length === 0 && missing.length === 0

    if (!verified) {
      this.exitCode = 1
    }

    const end = process.hrtime.bigint()
    const elapsed = end - start

    if (this.npm.config.get('json')) {
      this.appendOutput(this.makeJSON({ invalid, missing }))
    } else {
      const auditedPlural = this.audited > 1 ? 's' : ''
      const timing = `audited ${this.audited} package${auditedPlural} in ` +
                     `${Math.floor(Number(elapsed) / 1e9)}s`
      const verifiedPrefix = verified ? 'verified registry signatures, ' : ''
      this.appendOutput(`${verifiedPrefix}${timing}\n`)

      if (this.verified && !verified) {
        const verifiedClr = this.npm.color ? chalk.bold('verified') : 'verified'
        const msg = this.verified === 1 ?
          `${this.verified} package has a ${verifiedClr} registry signature\n` :
          `${this.verified} packages have ${verifiedClr} registry signatures\n`
        this.appendOutput(msg)
      }

      if (missing.length) {
        const logMissing = this.npm.config.get('log-missing-names')
        const missingClr = this.npm.color ? chalk.bold(chalk.magenta('missing')) : 'missing'
        const msg = missing.length === 1 ?
          `package has a ${missingClr} registry signature` :
          `packages have ${missingClr} registry signatures`
        this.appendOutput(
          `${missing.length} ${msg} but the registry is ` +
          `providing signing keys${logMissing ? ':\n' : ''}`
        )
        if (logMissing) {
          this.appendOutput(this.humanOutput(missing))
        } else {
          this.appendOutput(`  run \`npm audit signatures --log-missing-names\` for details`)
        }
      }

      if (invalid.length) {
        const invalidClr = this.npm.color ? chalk.bold(chalk.red('invalid')) : 'invalid'
        const msg = invalid.length === 1 ?
          `${invalid.length} package has an ${invalidClr} registry signature:\n` :
          `${invalid.length} packages have ${invalidClr} registry signatures:\n`
        this.appendOutput(
          `${missing.length ? '\n' : ''}${msg}`
        )
        this.appendOutput(this.humanOutput(invalid))
        const tamperMsg = invalid.length === 1 ?
          `\nSomeone might have tampered with this package since it was ` +
          `published on the registry!\n` :
          `\nSomeone might have tampered with these packages since they where ` +
          `published on the registry!\n`
        this.appendOutput(tamperMsg)
      }
    }
  }

  findAllRegistryUrls (edges) {
    return new Set(Array.from(edges, (edge) => {
      let alias = false
      try {
        alias = npa(edge.spec).subSpec
      } catch (err) {
      }
      const spec = npa(alias ? alias.name : edge.name)
      return this.getSpecRegistry(spec)
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

  getEdgeType (edge) {
    return edge.optional ? 'optionalDependencies'
      : edge.peer ? 'peerDependencies'
      : edge.dev ? 'devDependencies'
      : 'dependencies'
  }

  getEdgeSpec (edge) {
    let alias = false
    try {
      alias = npa(edge.spec).subSpec
    } catch (err) {
    }
    let spec
    try {
      spec = npa(`${alias ? alias.name : edge.name}@${edge.spec}`)
    } catch (_) {
      // Skip packages with invalid spec
      return
    }
    return spec
  }

  buildRegistryConfig (registry) {
    const keys = this.keys.get(registry) || []
    const parsedRegistry = new URL(registry)
    const regKey = `//${parsedRegistry.host}${parsedRegistry.pathname}`
    return {
      [`${regKey}:_keys`]: keys,
    }
  }

  getSpecRegistry (spec) {
    return fetch.pickRegistry(spec, this.npm.flatOptions)
  }

  async getVerifiedInfo (edge) {
    const type = this.getEdgeType(edge)
    // Skip potentially optional packages that are not on disk, as these could
    // be omitted during install
    if (edge.error === 'MISSING' && type !== 'dependencies') {
      return
    }

    const spec = this.getEdgeSpec(edge)
    // Skip invalid spec's
    if (!spec) {
      return
    }
    const node = edge.to || edge
    const { location } = node
    const name = spec.name
    const { version } = node.package || {}

    if (node.isWorkspace || // Skip local workspaces packages
        !version || // Skip packages that don't have a installed version, e.g. optonal dependencies
        !spec.registry) { // Skip if not from registry, e.g. git package
      return
    }

    for (const omitType of this.npm.config.get('omit')) {
      if (node[omitType]) {
        return
      }
    }

    this.audited += 1

    const registry = this.getSpecRegistry(spec)
    try {
      const {
        _integrity: integrity,
        _signatures,
        _resolved: resolved,
      } = await pacote.manifest(`${name}@${version}`, {
        verifySignatures: true, ...this.buildRegistryConfig(registry), ...this.npm.flatOptions,
      })
      const signatures = _signatures || []

      // Currently we only care about missing signatures on registries that provide a public key
      // We could make this configurable in the future with a strict/paranoid mode
      if (signatures.length) {
        this.verified += 1
      } else {
        this.missing.add({
          name,
          version,
          location,
          resolved,
          integrity,
          registry,
        })
      }
    } catch (e) {
      if (e.code === 'EINTEGRITYSIGNATURE') {
        const { signature, keyid, integrity, resolved } = e
        this.invalid.add({
          name,
          type,
          version,
          resolved,
          location,
          integrity,
          registry,
          signature,
          keyid,
        })
      } else {
        throw e
      }
    }
  }

  humanOutput (list) {
    const uniquePackages = new Set(Array.from(list, (v) => {
      let nameVersion = `${v.name}@${v.version}`
      if (this.npm.color) {
        nameVersion = chalk.red(nameVersion)
      }
      const registry = v.registry
      const suffix = registry !== defaultRegistry ? ` (${registry})` : ''
      return `${nameVersion}${suffix}`
    }))

    return [...uniquePackages].join('\n')
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
        throw Object.assign(new Error(argv[2] + ' not recognized'), {
          code: 'EUSAGE',
        })
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
    if (this.npm.config.get('global')) {
      throw Object.assign(
        new Error('`npm audit signatures` does not support global packages'), {
          code: 'EAUDITGLOBAL',
        }
      )
    }

    log.newItem('loading intalled dependencies')
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
