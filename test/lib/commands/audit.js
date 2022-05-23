const fs = require('fs')
const zlib = require('zlib')
const path = require('path')
const t = require('tap')

const { load: loadMockNpm, fake: mockNpm } = require('../../fixtures/mock-npm')
const MockRegistry = require('../../fixtures/mock-registry.js')

const gunzip = zlib.gunzipSync
const gzip = zlib.gzipSync

t.cleanSnapshot = str => str.replace(/packages in [0-9]+[a-z]+/g, 'packages in xxx')

const tree = {
  'package.json': JSON.stringify({
    name: 'test-dep',
    version: '1.0.0',
    dependencies: {
      'test-dep-a': '*',
    },
  }),
  'package-lock.json': JSON.stringify({
    name: 'test-dep',
    version: '1.0.0',
    lockfileVersion: 2,
    requires: true,
    packages: {
      '': {
        xname: 'scratch',
        version: '1.0.0',
        dependencies: {
          'test-dep-a': '*',
        },
        devDependencies: {},
      },
      'node_modules/test-dep-a': {
        name: 'test-dep-a',
        version: '1.0.0',
      },
    },
    dependencies: {
      'test-dep-a': {
        version: '1.0.0',
      },
    },
  }),
  'test-dep-a-vuln': {
    'package.json': JSON.stringify({
      name: 'test-dep-a',
      version: '1.0.0',
    }),
    'vulnerable.txt': 'vulnerable test-dep-a',
  },
  'test-dep-a-fixed': {
    'package.json': JSON.stringify({
      name: 'test-dep-a',
      version: '1.0.1',
    }),
    'fixed.txt': 'fixed test-dep-a',
  },
}

t.test('normal audit', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    prefixDir: tree,
  })
  const registry = new MockRegistry({
    tap: t,
    registry: npm.config.get('registry'),
  })

  const manifest = registry.manifest({
    name: 'test-dep-a',
    packuments: [{ version: '1.0.0' }, { version: '1.0.1' }],
  })
  await registry.package({ manifest })
  const advisory = registry.advisory({
    id: 100,
    vulnerable_versions: '<1.0.1',
  })
  const bulkBody = gzip(JSON.stringify({ 'test-dep-a': ['1.0.0'] }))
  registry.nock.post('/-/npm/v1/security/advisories/bulk', bulkBody)
    .reply(200, {
      'test-dep-a': [advisory],
    })

  await npm.exec('audit', [])
  t.ok(process.exitCode, 'would have exited uncleanly')
  process.exitCode = 0
  t.matchSnapshot(joinedOutput())
})

t.test('fallback audit ', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    prefixDir: tree,
  })
  const registry = new MockRegistry({
    tap: t,
    registry: npm.config.get('registry'),
  })
  const manifest = registry.manifest({
    name: 'test-dep-a',
    packuments: [{ version: '1.0.0' }, { version: '1.0.1' }],
  })
  await registry.package({ manifest })
  const advisory = registry.advisory({
    id: 100,
    module_name: 'test-dep-a',
    vulnerable_versions: '<1.0.1',
    findings: [{ version: '1.0.0', paths: ['test-dep-a'] }],
  })
  registry.nock
    .post('/-/npm/v1/security/advisories/bulk').reply(404)
    .post('/-/npm/v1/security/audits/quick', body => {
      const unzipped = JSON.parse(gunzip(Buffer.from(body, 'hex')))
      return t.match(unzipped, {
        name: 'test-dep',
        version: '1.0.0',
        requires: { 'test-dep-a': '*' },
        dependencies: { 'test-dep-a': { version: '1.0.0' } },
      })
    }).reply(200, {
      actions: [],
      muted: [],
      advisories: {
        100: advisory,
      },
      metadata: {
        vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        dependencies: 1,
        devDependencies: 0,
        optionalDependencies: 0,
        totalDependencies: 1,
      },
    })
  await npm.exec('audit', [])
  t.ok(process.exitCode, 'would have exited uncleanly')
  process.exitCode = 0
  t.matchSnapshot(joinedOutput())
})

t.test('json audit', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    prefixDir: tree,
    config: {
      json: true,
    },
  })
  const registry = new MockRegistry({
    tap: t,
    registry: npm.config.get('registry'),
  })

  const manifest = registry.manifest({
    name: 'test-dep-a',
    packuments: [{ version: '1.0.0' }, { version: '1.0.1' }],
  })
  await registry.package({ manifest })
  const advisory = registry.advisory({ id: 100 })
  const bulkBody = gzip(JSON.stringify({ 'test-dep-a': ['1.0.0'] }))
  registry.nock.post('/-/npm/v1/security/advisories/bulk', bulkBody)
    .reply(200, {
      'test-dep-a': [advisory],
    })

  await npm.exec('audit', [])
  t.ok(process.exitCode, 'would have exited uncleanly')
  process.exitCode = 0
  t.matchSnapshot(joinedOutput())
})

t.test('audit fix - bulk endpoint', async t => {
  const { npm, joinedOutput } = await loadMockNpm(t, {
    prefixDir: tree,
  })
  const registry = new MockRegistry({
    tap: t,
    registry: npm.config.get('registry'),
  })
  const manifest = registry.manifest({
    name: 'test-dep-a',
    packuments: [{ version: '1.0.0' }, { version: '1.0.1' }],
  })
  await registry.package({
    manifest,
    tarballs: {
      '1.0.1': path.join(npm.prefix, 'test-dep-a-fixed'),
    },
  })
  const advisory = registry.advisory({ id: 100, vulnerable_versions: '1.0.0' })
  registry.nock.post('/-/npm/v1/security/advisories/bulk', body => {
    const unzipped = JSON.parse(gunzip(Buffer.from(body, 'hex')))
    return t.same(unzipped, { 'test-dep-a': ['1.0.0'] })
  })
    .reply(200, { // first audit
      'test-dep-a': [advisory],
    })
    .post('/-/npm/v1/security/advisories/bulk', body => {
      const unzipped = JSON.parse(gunzip(Buffer.from(body, 'hex')))
      return t.same(unzipped, { 'test-dep-a': ['1.0.1'] })
    })
    .reply(200, { // after fix
      'test-dep-a': [],
    })
  await npm.exec('audit', ['fix'])
  t.matchSnapshot(joinedOutput())
  const pkg = fs.readFileSync(path.join(npm.prefix, 'package-lock.json'), 'utf8')
  t.matchSnapshot(pkg, 'lockfile has test-dep-a@1.0.1')
  t.ok(
    fs.existsSync(path.join(npm.prefix, 'node_modules', 'test-dep-a', 'fixed.txt')),
    'has test-dep-a@1.0.1 on disk'
  )
})

t.test('completion', async t => {
  const { npm } = await loadMockNpm(t)
  const audit = await npm.cmd('audit')
  t.test('fix', async t => {
    await t.resolveMatch(
      audit.completion({ conf: { argv: { remain: ['npm', 'audit'] } } }),
      ['fix'],
      'completes to fix'
    )
  })

  t.test('subcommand fix', async t => {
    await t.resolveMatch(
      audit.completion({ conf: { argv: { remain: ['npm', 'audit', 'fix'] } } }),
      [],
      'resolves to ?'
    )
  })

  t.test('subcommand not recognized', async t => {
    await t.rejects(audit.completion({ conf: { argv: { remain: ['npm', 'audit', 'repare'] } } }), {
      message: 'repare not recognized',
    })
  })
})

t.test('audit signatures', async t => {
  const mocks = {
    '../../../lib/utils/reify-finish.js': () => Promise.resolve(),
  }
  const Audit = t.mock('../../../lib/commands/audit.js', mocks)

  let npmOutput = []
  const joinedOutput = () => npmOutput.join('\n')

  let npm
  let audit
  let registry

  t.beforeEach(() => {
    npm = mockNpm({
      prefix: t.testdirName,
      color: false,
      config: {
        global: false,
        missing: false,
        json: false,
        omit: [],
      },
      flatOptions: {
        workspacesEnabled: true,
      },
      output: (str) => {
        npmOutput.push(str)
      },
    })

    audit = new Audit(npm)

    registry = new MockRegistry({
      tap: t,
      registry: npm.config.get('registry'),
    })
  })

  t.afterEach(() => {
    npmOutput = []
  })

  function validInstall () {
    return t.testdir({
      'package.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        dependencies: {
          'kms-demo': '1.0.0',
        },
      }),
      node_modules: {
        'kms-demo': {
          'package.json': JSON.stringify({
            name: 'kms-demo',
            version: '1.0.0',
          }),
        },
      },
      'package-lock.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        lockfileVersion: 2,
        requires: true,
        packages: {
          '': {
            name: 'scratch',
            version: '1.0.0',
            dependencies: {
              'kms-demo': '^1.0.0',
            },
          },
          'node_modules/kms-demo': {
            version: '1.0.0',
          },
        },
        dependencies: {
          'kms-demo': {
            version: '1.0.0',
          },
        },
      }),
    })
  }

  function validInstallWithAlias () {
    return t.testdir({
      'package.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        dependencies: {
          get: 'npm:node-fetch@^1.0.0',
        },
      }),
      node_modules: {
        get: {
          'package.json': JSON.stringify({
            name: 'node-fetch',
            version: '1.7.1',
          }),
        },
      },
      'package-lock.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        lockfileVersion: 2,
        requires: true,
        packages: {
          '': {
            name: 'test-dep',
            version: '1.0.0',
            dependencies: {
              get: 'npm:node-fetch@^1.0.0',
            },
          },
          'node_modules/demo': {
            name: 'node-fetch',
            version: '1.7.1',
          },
        },
        dependencies: {
          get: {
            version: 'npm:kms-demo@1.7.1',
          },
        },
      }),
    })
  }

  function noInstall () {
    return t.testdir({
      'package.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        dependencies: {
          'kms-demo': '1.0.0',
        },
      }),
      'package-lock.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        lockfileVersion: 2,
        requires: true,
        packages: {
          '': {
            name: 'scratch',
            version: '1.0.0',
            dependencies: {
              'kms-demo': '^1.0.0',
            },
          },
          'node_modules/kms-demo': {
            version: '1.0.0',
          },
        },
        dependencies: {
          'kms-demo': {
            version: '1.0.0',
          },
        },
      }),
    })
  }

  function workspaceInstall () {
    return t.testdir({
      'package.json': JSON.stringify({
        name: 'workspaces-project',
        version: '1.0.0',
        workspaces: ['packages/*'],
        dependencies: {
          'kms-demo': '^1.0.0',
        },
      }),
      node_modules: {
        a: t.fixture('symlink', '../packages/a'),
        b: t.fixture('symlink', '../packages/b'),
        c: t.fixture('symlink', '../packages/c'),
        'kms-demo': {
          'package.json': JSON.stringify({
            name: 'kms-demo',
            version: '1.0.0',
          }),
        },
        async: {
          'package.json': JSON.stringify({
            name: 'async',
            version: '2.5.0',
          }),
        },
        'light-cycle': {
          'package.json': JSON.stringify({
            name: 'light-cycle',
            version: '1.4.2',
          }),
        },
      },
      packages: {
        a: {
          'package.json': JSON.stringify({
            name: 'a',
            version: '1.0.0',
            dependencies: {
              b: '^1.0.0',
              async: '^2.0.0',
            },
          }),
        },
        b: {
          'package.json': JSON.stringify({
            name: 'b',
            version: '1.0.0',
            dependencies: {
              'light-cycle': '^1.0.0',
            },
          }),
        },
        c: {
          'package.json': JSON.stringify({
            name: 'c',
            version: '1.0.0',
          }),
        },
      },
    })
  }

  function installWithMultipleDeps () {
    return t.testdir({
      'package.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        dependencies: {
          'kms-demo': '^1.0.0',
        },
        devDependencies: {
          async: '~1.1.0',
        },
      }),
      node_modules: {
        'kms-demo': {
          'package.json': JSON.stringify({
            name: 'kms-demo',
            version: '1.0.0',
          }),
        },
        async: {
          'package.json': JSON.stringify({
            name: 'async',
            version: '1.1.1',
          }),
        },
      },
      'package-lock.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        lockfileVersion: 2,
        requires: true,
        packages: {
          '': {
            name: 'scratch',
            version: '1.0.0',
            dependencies: {
              'kms-demo': '^1.0.0',
            },
            devDependencies: {
              async: '~1.0.0',
            },
          },
          'node_modules/kms-demo': {
            version: '1.0.0',
          },
          'node_modules/async': {
            version: '1.1.1',
          },
        },
        dependencies: {
          'kms-demo': {
            version: '1.0.0',
          },
          async: {
            version: '1.1.1',
          },
        },
      }),
    })
  }

  function installWithPeerDeps () {
    return t.testdir({
      'package.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        peerDependencies: {
          'kms-demo': '^1.0.0',
        },
      }),
      node_modules: {
        'kms-demo': {
          'package.json': JSON.stringify({
            name: 'kms-demo',
            version: '1.0.0',
          }),
        },
      },
      'package-lock.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        lockfileVersion: 2,
        requires: true,
        packages: {
          '': {
            name: 'scratch',
            version: '1.0.0',
            peerDependencies: {
              'kms-demo': '^1.0.0',
            },
          },
          'node_modules/kms-demo': {
            version: '1.0.0',
          },
        },
        dependencies: {
          'kms-demo': {
            version: '1.0.0',
          },
        },
      }),
    })
  }

  function installWithOptionalDeps () {
    return t.testdir({
      'package.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        dependencies: {
          'kms-demo': '^1.0.0',
        },
        optionalDependencies: {
          lorem: '^1.0.0',
        },
      }, null, 2),
      node_modules: {
        'kms-demo': {
          'package.json': JSON.stringify({
            name: 'kms-demo',
            version: '1.0.0',
          }),
        },
      },
      'package-lock.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        lockfileVersion: 2,
        requires: true,
        packages: {
          '': {
            name: 'scratch',
            version: '1.0.0',
            dependencies: {
              'kms-demo': '^1.0.0',
            },
            optionalDependencies: {
              lorem: '^1.0.0',
            },
          },
          'node_modules/kms-demo': {
            version: '1.0.0',
          },
        },
        dependencies: {
          'kms-demo': {
            version: '1.0.0',
          },
        },
      }),
    })
  }

  function installWithMultipleRegistries () {
    return t.testdir({
      'package.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        dependencies: {
          '@npmcli/arborist': '^1.0.0',
          'kms-demo': '^1.0.0',
        },
      }),
      node_modules: {
        '@npmcli/arborist': {
          'package.json': JSON.stringify({
            name: '@npmcli/arborist',
            version: '1.0.14',
          }),
        },
        'kms-demo': {
          'package.json': JSON.stringify({
            name: 'kms-demo',
            version: '1.0.0',
          }),
        },
      },
      'package-lock.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        lockfileVersion: 2,
        requires: true,
        packages: {
          '': {
            name: 'test-dep',
            version: '1.0.0',
            dependencies: {
              '@npmcli/arborist': '^1.0.0',
              'kms-demo': '^1.0.0',
            },
          },
          'node_modules/@npmcli/arborist': {
            version: '1.0.14',
          },
          'node_modules/kms-demo': {
            version: '1.0.0',
          },
        },
        dependencies: {
          '@npmcli/arborist': {
            version: '1.0.14',
          },
          'kms-demo': {
            version: '1.0.0',
          },
        },
      }),
    })
  }

  function installWithThirdPartyRegistry () {
    return t.testdir({
      'package.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        dependencies: {
          '@npmcli/arborist': '^1.0.0',
        },
      }),
      node_modules: {
        '@npmcli/arborist': {
          'package.json': JSON.stringify({
            name: '@npmcli/arborist',
            version: '1.0.14',
          }),
        },
      },
      'package-lock.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
        lockfileVersion: 2,
        requires: true,
        packages: {
          '': {
            name: 'test-dep',
            version: '1.0.0',
            dependencies: {
              '@npmcli/arborist': '^1.0.0',
            },
          },
          'node_modules/@npmcli/arborist': {
            version: '1.0.14',
          },
        },
        dependencies: {
          '@npmcli/arborist': {
            version: '1.0.14',
          },
        },
      }),
    })
  }

  async function manifestWithValidSigs () {
    const manifest = registry.manifest({
      name: 'kms-demo',
      packuments: [{
        version: '1.0.0',
        dist: {
          tarball: 'https://registry.npmjs.org/kms-demo/-/kms-demo-1.0.0.tgz',
          integrity: 'sha512-QqZ7VJ/8xPkS9s2IWB7Shj3qTJdcRyeXKbPQnsZjsPEwvutGv0EGeVchPca' +
                     'uoiDFJlGbZMFq5GDCurAGNSghJQ==',
          signatures: [
            {
              keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
              sig: 'MEUCIDrLNspFeU5NZ6d55ycVBZIMXnPJi/XnI1Y2dlJvK8P1AiEAnXjn1IOMUd+U7YfPH' +
                   '+FNjwfLq+jCwfH8uaxocq+mpPk=',
            },
          ],
        },
      }],
    })
    await registry.package({ manifest })
  }

  async function manifestWithInvalidSigs (name = 'kms-demo', version = '1.0.0') {
    const manifest = registry.manifest({
      name,
      packuments: [{
        version,
        dist: {
          tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
          integrity: 'sha512-QqZ7VJ/8xPkS9s2IWB7Shj3qTJdcRyeXKbPQnsZjsPEwvutGv0EGeVchPca' +
                     'uoiDFJlGbZMFq5GDCurAGNSghJQ==',
          signatures: [
            {
              keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
              sig: 'bogus',
            },
          ],
        },
      }],
    })
    await registry.package({ manifest })
  }

  async function manifestWithoutSigs (name = 'kms-demo', version = '1.0.0') {
    const manifest = registry.manifest({
      name,
      packuments: [{
        version,
      }],
    })
    await registry.package({ manifest })
  }

  function validKeys () {
    registry.nock.get('/-/npm/v1/keys')
      .reply(200, {
        keys: [{
          expires: null,
          keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
          keytype: 'ecdsa-sha2-nistp256',
          scheme: 'ecdsa-sha2-nistp256',
          key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+' +
               'IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==',
        }],
      })
  }

  function mismatchingKeys () {
    registry.nock.get('/-/npm/v1/keys')
      .reply(200, {
        keys: [{
          expires: null,
          keyid: 'SHA256:2l3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
          keytype: 'ecdsa-sha2-nistp256',
          scheme: 'ecdsa-sha2-nistp256',
          key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+' +
               'IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==',
        }],
      })
  }

  function expiredKeys () {
    registry.nock.get('/-/npm/v1/keys')
      .reply(200, {
        keys: [{
          expires: '2021-01-11T15:45:42.144Z',
          keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
          keytype: 'ecdsa-sha2-nistp256',
          scheme: 'ecdsa-sha2-nistp256',
          key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+' +
               'IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==',
        }],
      })
  }

  t.test('with valid signatures', async t => {
    npm.prefix = validInstall()
    await manifestWithValidSigs()
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 0, 'should exit successfully')
    process.exitCode = 0
    t.match(joinedOutput(), /verified registry signatures, audited 1 package/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('with valid signatures using alias', async t => {
    npm.prefix = validInstallWithAlias()
    const manifest = registry.manifest({
      name: 'node-fetch',
      packuments: [{
        version: '1.7.1',
        dist: {
          tarball: 'https://registry.npmjs.org/node-fetch/-/node-fetch-1.7.1.tgz',
          integrity: 'sha512-j8XsFGCLw79vWXkZtMSmmLaOk9z5SQ9bV/tkbZVCqvgwzrjAGq6' +
                     '6igobLofHtF63NvMTp2WjytpsNTGKa+XRIQ==',
          signatures: [
            {
              keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
              sig: 'MEYCIQDEn2XrrMXlRm+wh2tOIUyb0Km3ZujfT+6Mf61OXGK9zQIhANnPauUwx3' +
                   'N9RcQYQakDpOmLvYzNkySh7fmzmvyhk21j',
            },
          ],
        },
      }],
    })
    await registry.package({ manifest })
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 0, 'should exit successfully')
    process.exitCode = 0
    t.match(joinedOutput(), /verified registry signatures, audited 1 package/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('with bundled and peer deps and no signatures', async t => {
    npm.prefix = installWithPeerDeps()
    await manifestWithValidSigs()
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 0, 'should exit successfully')
    process.exitCode = 0
    t.match(joinedOutput(), /verified registry signatures, audited 1 package/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('with invalid signatures', async t => {
    npm.prefix = validInstall()
    await manifestWithInvalidSigs()
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 1, 'should exit with error')
    process.exitCode = 0
    t.match(joinedOutput(), /invalid registry signature/)
    t.match(joinedOutput(), /kms-demo@1.0.0/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('with valid and missing signatures', async t => {
    npm.prefix = installWithMultipleDeps()
    await manifestWithValidSigs()
    await manifestWithoutSigs('async', '1.1.1')
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 1, 'should exit with error')
    process.exitCode = 0
    t.match(joinedOutput(), /audited 2 packages/)
    t.match(joinedOutput(), /verified registry signatures/)
    t.match(joinedOutput(), /missing registry signature/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('with both invalid and missing signatures', async t => {
    npm.prefix = installWithMultipleDeps()
    await manifestWithInvalidSigs()
    await manifestWithoutSigs('async', '1.1.1')
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 1, 'should exit with error')
    process.exitCode = 0
    t.match(joinedOutput(), /audited 2 packages/)
    t.match(joinedOutput(), /invalid/)
    t.match(joinedOutput(), /missing/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('with multiple invalid signatures', async t => {
    npm.prefix = installWithMultipleDeps()
    await manifestWithInvalidSigs('kms-demo', '1.0.0')
    await manifestWithInvalidSigs('async', '1.1.1')
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 1, 'should exit with error')
    process.exitCode = 0
    t.matchSnapshot(joinedOutput())
  })

  t.test('with multiple missing signatures', async t => {
    npm.prefix = installWithMultipleDeps()
    await manifestWithoutSigs('kms-demo', '1.0.0')
    await manifestWithoutSigs('async', '1.1.1')
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 1, 'should exit with error')
    process.exitCode = 0
    t.matchSnapshot(joinedOutput())
  })

  t.test('with signatures but no public keys', async t => {
    npm.prefix = validInstall()
    await manifestWithValidSigs()
    registry.nock.get('/-/npm/v1/keys')
      .reply(404)

    await t.rejects(
      audit.exec(['signatures']),
      /no corresponding public key can be found on https:\/\/registry.npmjs.org\/-\/npm\/v1\/keys/,
      'should throw with error'
    )
  })

  t.test('with signatures but the public keys are expired', async t => {
    npm.prefix = validInstall()
    await manifestWithValidSigs()
    expiredKeys()

    await t.rejects(
      audit.exec(['signatures']),
      /the corresponding public key on https:\/\/registry.npmjs.org\/-\/npm\/v1\/keys has expired/,
      'should throw with error'
    )
  })

  t.test('with signatures but the public keyid does not match', async t => {
    npm.prefix = validInstall()
    await manifestWithValidSigs()
    mismatchingKeys()

    await t.rejects(
      audit.exec(['signatures']),
      /no corresponding public key can be found on https:\/\/registry.npmjs.org\/-\/npm\/v1\/keys/,
      'should throw with error'
    )
  })

  t.test('with keys but missing signature', async t => {
    npm.prefix = validInstall()
    await manifestWithoutSigs()
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 1, 'should exit with error')
    process.exitCode = 0
    t.match(
      joinedOutput(),
      /registry is providing signing keys/
    )
    t.matchSnapshot(joinedOutput())
  })

  t.test('output details about missing signatures', async t => {
    npm.prefix = validInstall()
    npm.config.set('missing', true)
    await manifestWithoutSigs()
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 1, 'should exit with error')
    process.exitCode = 0
    t.match(
      joinedOutput(),
      /kms-demo/
    )
    t.matchSnapshot(joinedOutput())
  })

  t.test('json output with valid signatures', async t => {
    npm.prefix = validInstall()
    npm.config.set('json', true)
    await manifestWithValidSigs()
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 0, 'should exit successfully')
    process.exitCode = 0
    t.match(joinedOutput(), /{}/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('json output with invalid signatures', async t => {
    npm.prefix = validInstall()
    npm.config.set('json', true)
    await manifestWithInvalidSigs()
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 1, 'should exit with error')
    process.exitCode = 0
    t.match(joinedOutput(), /"invalid": {\n\s+"node_modules\/kms-demo": {/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('json output with invalid and missing signatures', async t => {
    npm.prefix = installWithMultipleDeps()
    npm.config.set('json', true)
    await manifestWithInvalidSigs()
    await manifestWithoutSigs('async', '1.1.1')
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 1, 'should exit with error')
    process.exitCode = 0
    t.match(joinedOutput(), /"invalid": {\n\s+"node_modules\/kms-demo": {/)
    t.match(joinedOutput(), /"missing": {\n\s+"node_modules\/async": {/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('omit dev dependencies with missing signature', async t => {
    npm.prefix = installWithMultipleDeps()
    npm.config.set('omit', ['dev'])
    await manifestWithValidSigs()
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 0, 'should exit successfully')
    process.exitCode = 0
    t.match(joinedOutput(), /verified registry signatures, audited 1 package/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('third-party registry without keys does not verify', async t => {
    npm.prefix = installWithThirdPartyRegistry()
    const registryUrl = 'https://verdaccio-clone.org'
    npm.flatOptions['@npmcli:registry'] = registryUrl
    registry = new MockRegistry({
      tap: t,
      registry: registryUrl,
    })

    t.equal(process.exitCode, 0, 'should exit successfully')
    process.exitCode = 0
    t.match(joinedOutput(), '')
    t.matchSnapshot(joinedOutput())
  })

  t.test('third-party registry with keys and signatures', async t => {
    npm.prefix = installWithThirdPartyRegistry()
    const registryUrl = 'https://verdaccio-clone.org'
    npm.flatOptions['@npmcli:registry'] = registryUrl
    const thirdPartyRegistry = new MockRegistry({
      tap: t,
      registry: registryUrl,
    })

    const manifest = thirdPartyRegistry.manifest({
      name: '@npmcli/arborist',
      packuments: [{
        version: '1.0.14',
        dist: {
          tarball: 'https://registry.npmjs.org/@npmcli/arborist/-/@npmcli/arborist-1.0.14.tgz',
          integrity: 'sha512-caa8hv5rW9VpQKk6tyNRvSaVDySVjo9GkI7Wj/wcsFyxPm3tYrE' +
                     'sFyTjSnJH8HCIfEGVQNjqqKXaXLFVp7UBag==',
          signatures: [
            {
              keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
              sig: 'MEUCIAvNpR3G0j7WOPUuVMhE0ZdM8PnDNcsoeFD8Iwz9YWIMAiEAn8cicDC2' +
                   'Sf9MFQydqTv6S5XYsAh9Af1sig1nApNI11M=',
            },
          ],
        },
      }],
    })
    await thirdPartyRegistry.package({ manifest })
    thirdPartyRegistry.nock.get('/-/npm/v1/keys')
      .reply(200, {
        keys: [{
          expires: null,
          keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
          keytype: 'ecdsa-sha2-nistp256',
          scheme: 'ecdsa-sha2-nistp256',
          key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+' +
               'IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==',
        }],
      })

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 0, 'should exit successfully')
    process.exitCode = 0
    t.match(joinedOutput(), /verified registry signatures, audited 1 package/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('third-party registry with invalid signatures errors', async t => {
    npm.prefix = installWithThirdPartyRegistry()
    const registryUrl = 'https://verdaccio-clone.org'
    npm.flatOptions['@npmcli:registry'] = registryUrl
    const thirdPartyRegistry = new MockRegistry({
      tap: t,
      registry: registryUrl,
    })

    const manifest = thirdPartyRegistry.manifest({
      name: '@npmcli/arborist',
      packuments: [{
        version: '1.0.14',
        dist: {
          tarball: 'https://registry.npmjs.org/@npmcli/arborist/-/@npmcli/arborist-1.0.14.tgz',
          integrity: 'sha512-caa8hv5rW9VpQKk6tyNRvSaVDySVjo9GkI7Wj/wcsFyxPm3tYrE' +
                     'sFyTjSnJH8HCIfEGVQNjqqKXaXLFVp7UBag==',
          signatures: [
            {
              keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
              sig: 'bogus',
            },
          ],
        },
      }],
    })
    await thirdPartyRegistry.package({ manifest })
    thirdPartyRegistry.nock.get('/-/npm/v1/keys')
      .reply(200, {
        keys: [{
          expires: null,
          keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
          keytype: 'ecdsa-sha2-nistp256',
          scheme: 'ecdsa-sha2-nistp256',
          key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+' +
               'IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==',
        }],
      })

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 1, 'should exit with error')
    process.exitCode = 0
    t.match(joinedOutput(), /https:\/\/verdaccio-clone.org/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('third-party registry with keys and missing signatures errors', async t => {
    npm.prefix = installWithThirdPartyRegistry()
    const registryUrl = 'https://verdaccio-clone.org'
    npm.flatOptions['@npmcli:registry'] = registryUrl
    const thirdPartyRegistry = new MockRegistry({
      tap: t,
      registry: registryUrl,
    })

    const manifest = thirdPartyRegistry.manifest({
      name: '@npmcli/arborist',
      packuments: [{
        version: '1.0.14',
        dist: {
          tarball: 'https://registry.npmjs.org/@npmcli/arborist/-/@npmcli/arborist-1.0.14.tgz',
          integrity: 'sha512-caa8hv5rW9VpQKk6tyNRvSaVDySVjo9GkI7Wj/wcsFyxPm3tYrE' +
                     'sFyTjSnJH8HCIfEGVQNjqqKXaXLFVp7UBag==',
        },
      }],
    })
    await thirdPartyRegistry.package({ manifest })
    thirdPartyRegistry.nock.get('/-/npm/v1/keys')
      .reply(200, {
        keys: [{
          expires: null,
          keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
          keytype: 'ecdsa-sha2-nistp256',
          scheme: 'ecdsa-sha2-nistp256',
          key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+' +
               'IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==',
        }],
      })

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 1, 'should exit with error')
    process.exitCode = 0
    t.match(joinedOutput(), /1 package has a missing registry signature/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('multiple registries with keys and signatures', async t => {
    npm.prefix = installWithMultipleRegistries()
    const registryUrl = 'https://verdaccio-clone.org'
    npm.flatOptions['@npmcli:registry'] = registryUrl
    const thirdPartyRegistry = new MockRegistry({
      tap: t,
      registry: registryUrl,
    })
    await manifestWithValidSigs()
    validKeys()

    const manifest = thirdPartyRegistry.manifest({
      name: '@npmcli/arborist',
      packuments: [{
        version: '1.0.14',
        dist: {
          tarball: 'https://registry.npmjs.org/@npmcli/arborist/-/@npmcli/arborist-1.0.14.tgz',
          integrity: 'sha512-caa8hv5rW9VpQKk6tyNRvSaVDySVjo9GkI7Wj/wcsFyxPm3tYrE' +
                     'sFyTjSnJH8HCIfEGVQNjqqKXaXLFVp7UBag==',
          signatures: [
            {
              keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
              sig: 'MEUCIAvNpR3G0j7WOPUuVMhE0ZdM8PnDNcsoeFD8Iwz9YWIMAiEAn8cicDC2' +
                   'Sf9MFQydqTv6S5XYsAh9Af1sig1nApNI11M=',
            },
          ],
        },
      }],
    })
    await thirdPartyRegistry.package({ manifest })
    thirdPartyRegistry.nock.get('/-/npm/v1/keys')
      .reply(200, {
        keys: [{
          expires: null,
          keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
          keytype: 'ecdsa-sha2-nistp256',
          scheme: 'ecdsa-sha2-nistp256',
          key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+' +
               'IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==',
        }],
      })

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 0, 'should exit successfully')
    process.exitCode = 0
    t.match(joinedOutput(), /verified registry signatures, audited 2 packages/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('errors with an empty install', async t => {
    npm.prefix = t.testdir({
      'package.json': JSON.stringify({
        name: 'test-dep',
        version: '1.0.0',
      }),
    })

    await t.rejects(
      audit.exec(['signatures']),
      /No dependencies found in current install/
    )
  })

  t.test('errors when the keys endpoint errors', async t => {
    npm.prefix = installWithMultipleDeps()
    registry.nock.get('/-/npm/v1/keys')
      .reply(500, { error: 'keys broke' })

    await t.rejects(
      audit.exec(['signatures']),
      /keys broke/
    )
  })

  t.test('ignores optional dependencies', async t => {
    npm.prefix = installWithOptionalDeps()

    await manifestWithValidSigs()
    validKeys()

    await audit.exec(['signatures'])

    t.equal(process.exitCode, 0, 'should exit successfully')
    process.exitCode = 0
    t.match(joinedOutput(), /verified registry signatures, audited 1 package/)
    t.matchSnapshot(joinedOutput())
  })

  t.test('errors when no installed dependencies', async t => {
    npm.prefix = noInstall()
    validKeys()

    await t.rejects(
      audit.exec(['signatures']),
      /No dependencies found in current install/
    )
  })

  t.test('should skip missing non-prod deps', async t => {
    npm.prefix = t.testdir({
      'package.json': JSON.stringify({
        name: 'delta',
        version: '1.0.0',
        devDependencies: {
          chai: '^1.0.0',
        },
      }, null, 2),
      node_modules: {},
    })

    validKeys()

    await t.rejects(
      audit.exec(['signatures']),
      /No dependencies found in current install/
    )
  })

  t.test('should skip invalid pkg ranges', async t => {
    npm.prefix = t.testdir({
      'package.json': JSON.stringify({
        name: 'delta',
        version: '1.0.0',
        dependencies: {
          cat: '>=^2',
        },
      }, null, 2),
      node_modules: {
        cat: {
          'package.json': JSON.stringify({
            name: 'cat',
            version: '1.0.0',
          }, null, 2),
        },
      },
    })
    validKeys()

    await t.rejects(
      audit.exec(['signatures']),
      /No dependencies found in current install/
    )
  })

  t.test('should skip git specs', async t => {
    npm.prefix = t.testdir({
      'package.json': JSON.stringify({
        name: 'delta',
        version: '1.0.0',
        dependencies: {
          cat: 'github:username/foo',
        },
      }, null, 2),
      node_modules: {
        cat: {
          'package.json': JSON.stringify({
            name: 'cat',
            version: '1.0.0',
          }, null, 2),
        },
      },
    })

    validKeys()

    await t.rejects(
      audit.exec(['signatures']),
      /No dependencies found in current install/
    )
  })

  t.test('with color output enabled', async t => {
    t.test('with invalid signatures', async t => {
      npm.prefix = validInstall()
      npm.color = true
      await manifestWithInvalidSigs()
      validKeys()

      await audit.exec(['signatures'])

      t.equal(process.exitCode, 1, 'should exit with error')
      process.exitCode = 0
      t.match(
        joinedOutput(),
        /* eslint-disable-next-line no-control-regex */
        /\u001b\[1m\u001b\[31minvalid\u001b\[39m\u001b\[22m registry signature/
      )
      t.matchSnapshot(joinedOutput())
    })

    t.test('with both valid and missing signatures', async t => {
      npm.prefix = installWithMultipleDeps()
      npm.color = true
      await manifestWithValidSigs()
      await manifestWithoutSigs('async', '1.1.1')
      validKeys()

      await audit.exec(['signatures'])

      t.equal(process.exitCode, 1, 'should exit with error')
      process.exitCode = 0
      t.matchSnapshot(joinedOutput())
    })

    t.test('with multiple invalid signatures', async t => {
      npm.prefix = installWithMultipleDeps()
      npm.color = true
      await manifestWithInvalidSigs('kms-demo', '1.0.0')
      await manifestWithInvalidSigs('async', '1.1.1')
      validKeys()

      await audit.exec(['signatures'])

      t.equal(process.exitCode, 1, 'should exit with error')
      process.exitCode = 0
      t.matchSnapshot(joinedOutput())
    })

    t.test('with multiple missing signatures', async t => {
      npm.prefix = installWithMultipleDeps()
      npm.color = true
      await manifestWithoutSigs('kms-demo', '1.0.0')
      await manifestWithoutSigs('async', '1.1.1')
      validKeys()

      await audit.exec(['signatures'])

      t.equal(process.exitCode, 1, 'should exit with error')
      process.exitCode = 0
      t.matchSnapshot(joinedOutput())
    })
  })

  t.test('workspaces', async t => {
    t.test('verifies registry deps and ignores local workspace deps', async t => {
      npm.prefix = workspaceInstall()
      await manifestWithValidSigs()
      const asyncManifest = registry.manifest({
        name: 'async',
        packuments: [{
          version: '2.5.0',
          dist: {
            tarball: 'https://registry.npmjs.org/async/-/async-2.5.0.tgz',
            integrity: 'sha512-e+lJAJeNWuPCNyxZKOBdaJGyLGHugXVQtrAwtuAe2vhxTYxFT'
                       + 'KE73p8JuTmdH0qdQZtDvI4dhJwjZc5zsfIsYw==',
            signatures: [
              {
                keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
                sig: 'MEUCIQCM8cX2U3IVZKKhzQx1w5AlNSDUI+fVf4857K1qT0NTNgIgdT4qwEl' +
                     '/kg2vU1uIWUI0bGikRvVHCHlRs1rgjPMpRFA=',
              },
            ],
          },
        }],
      })
      const lightCycleManifest = registry.manifest({
        name: 'light-cycle',
        packuments: [{
          version: '1.4.2',
          dist: {
            tarball: 'https://registry.npmjs.org/light-cycle/-/light-cycle-1.4.2.tgz',
            integrity: 'sha512-badZ3KMUaGwQfVcHjXTXSecYSXxT6f99bT+kVzBqmO10U1UNlE' +
                       'thJ1XAok97E4gfDRTA2JJ3r0IeMPtKf0EJMw==',
            signatures: [
              {
                keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
                sig: 'MEUCIQDXjoxQz4MzPqaIuy2RJmBlcFp0UD3h9EhKZxxEz9IYZAIgLO0znG5' +
                     'aGciTAg4u8fE0/UXBU4gU7JcvTZGxW2BmKGw=',
              },
            ],
          },
        }],
      })
      await registry.package({ manifest: asyncManifest })
      await registry.package({ manifest: lightCycleManifest })
      validKeys()

      await audit.exec(['signatures'])

      t.equal(process.exitCode, 0, 'should exit successfully')
      process.exitCode = 0
      t.match(joinedOutput(), /verified registry signatures, audited 3 packages/)
      t.matchSnapshot(joinedOutput())
    })

    t.test('verifies registry deps when filtering by workspace name', async t => {
      npm.prefix = workspaceInstall()
      npm.localPrefix = npm.prefix
      const asyncManifest = registry.manifest({
        name: 'async',
        packuments: [{
          version: '2.5.0',
          dist: {
            tarball: 'https://registry.npmjs.org/async/-/async-2.5.0.tgz',
            integrity: 'sha512-e+lJAJeNWuPCNyxZKOBdaJGyLGHugXVQtrAwtuAe2vhxTYxFT'
                       + 'KE73p8JuTmdH0qdQZtDvI4dhJwjZc5zsfIsYw==',
            signatures: [
              {
                keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
                sig: 'MEUCIQCM8cX2U3IVZKKhzQx1w5AlNSDUI+fVf4857K1qT0NTNgIgdT4qwEl' +
                     '/kg2vU1uIWUI0bGikRvVHCHlRs1rgjPMpRFA=',
              },
            ],
          },
        }],
      })
      const lightCycleManifest = registry.manifest({
        name: 'light-cycle',
        packuments: [{
          version: '1.4.2',
          dist: {
            tarball: 'https://registry.npmjs.org/light-cycle/-/light-cycle-1.4.2.tgz',
            integrity: 'sha512-badZ3KMUaGwQfVcHjXTXSecYSXxT6f99bT+kVzBqmO10U1UNlE' +
                       'thJ1XAok97E4gfDRTA2JJ3r0IeMPtKf0EJMw==',
            signatures: [
              {
                keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
                sig: 'MEUCIQDXjoxQz4MzPqaIuy2RJmBlcFp0UD3h9EhKZxxEz9IYZAIgLO0znG5' +
                     'aGciTAg4u8fE0/UXBU4gU7JcvTZGxW2BmKGw=',
              },
            ],
          },
        }],
      })
      await registry.package({ manifest: asyncManifest })
      await registry.package({ manifest: lightCycleManifest })
      validKeys()

      await audit.execWorkspaces(['signatures'], ['./packages/a'])

      t.equal(process.exitCode, 0, 'should exit successfully')
      process.exitCode = 0
      t.match(joinedOutput(), /verified registry signatures, audited 2 packages/)
      t.matchSnapshot(joinedOutput())
    })

    // TODO: This should verify kms-demo, but doesn't because arborist filters
    // workspace deps even if they're also root deps
    t.test('verifies registry dep if workspaces is disabled', async t => {
      npm.prefix = workspaceInstall()
      npm.flatOptions.workspacesEnabled = false

      await t.rejects(
        audit.exec(['signatures']),
        /No dependencies found in current install/
      )
    })
  })
})
