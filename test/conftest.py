import asyncio
import os
import subprocess
import time
import base64
import requests
import pytest
import aiodxf
import aiodxf.main

# From https://pytest.org/latest/example/simple.html#making-test-result-information-available-in-fixtures
# pylint: disable=no-member,unused-argument
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()
    if rep.failed:
        setattr(item.getparent(pytest.Module), 'rep_failed', True)

_here = os.path.join(os.path.dirname(__file__))
_fixture_dir = os.path.join(_here, 'fixtures')
_registry_dir = os.path.join(_here, 'registry')
_auth_dir = os.path.join(_here, 'auth')
_remove_container = os.path.join(_here, 'remove_container.sh')
_username = 'fred'
_password = '!WordPass0$'

DEVNULL = open(os.devnull, 'wb')

def gc():
    subprocess.check_call(['docker', 'exec', 'dxf_registry', 'bin/registry', 'garbage-collect', '/etc/docker/registry/config.yml'])

def copy_registry_image(regver):
    # pylint: disable=redefined-outer-name
    tag = 'localhost:5000/test/registry:{}'.format(regver)
    subprocess.check_call(['docker',
                           'tag',
                           'registry:{}'.format(regver),
                           tag])
    subprocess.check_call(['docker',
                           'login',
                           '-u',
                           pytest.username,
                           '-p',
                           pytest.password,
                           'localhost:5000'])
    subprocess.check_call(['docker', 'push', tag])
    subprocess.check_call(['docker', 'rmi', tag])

def pytest_configure(config):
    setattr(pytest, 'blob1_file', os.path.join(_fixture_dir, 'blob1'))
    setattr(pytest, 'blob2_file', os.path.join(_fixture_dir, 'blob2'))
    setattr(pytest, 'blob3_file', os.path.join(_fixture_dir, 'blob3'))
    setattr(pytest, 'blob4_file', os.path.join(_fixture_dir, 'blob4'))

    setattr(pytest, 'blob1_hash', os.environ['HASH1'])
    setattr(pytest, 'blob2_hash', os.environ['HASH2'])
    setattr(pytest, 'blob3_hash', os.environ['HASH3'])
    setattr(pytest, 'blob4_hash', os.environ['HASH4'])

    setattr(pytest, 'blob1_size', 1 * 1024 * 1024)
    setattr(pytest, 'blob2_size', 2 * 1024 * 1024)
    setattr(pytest, 'blob3_size', 2 * 1024 * 1024)
    setattr(pytest, 'blob4_size', 2 * 1024 * 1024)

    setattr(pytest, 'username', _username)
    setattr(pytest, 'password', _password)
    # pylint: disable=protected-access
    setattr(pytest, 'authorization', 'Basic ' + base64.b64encode(aiodxf._to_bytes_2and3(_username + ':' + _password)).decode('utf-8'))

    setattr(pytest, 'repo', 'foo/bar')

    setattr(pytest, 'gc', gc)

    setattr(pytest, 'copy_registry_image', copy_registry_image)

async def _auth_up(dxf_obj, response):
    # pylint: disable=redefined-outer-name
    await dxf_obj.authenticate(pytest.username, pytest.password, response=response)

async def _auth_authz(dxf_obj, response):
    # pylint: disable=redefined-outer-name
    await dxf_obj.authenticate(authorization=pytest.authorization, response=response)

def _get_registry_digest(regver):
    # pylint: disable=redefined-outer-name
    s = subprocess.check_output(['docker',
                                 'inspect',
                                 'registry:{}'.format(regver),
                                 '--format={{.Id}}']).rstrip().decode('utf-8')
    aiodxf.split_digest(s)
    return s

def _setup_fixture(request):
    setattr(request.node, 'rep_failed', False)
    def cleanup():
        if getattr(request.node, 'rep_failed', False):
            subprocess.call(['docker', 'logs', 'dxf_registry'])
            subprocess.call(['docker', 'logs', 'dxf_auth'])
        subprocess.call([_remove_container, 'dxf_registry'])
        subprocess.call([_remove_container, 'dxf_auth'])
    request.addfinalizer(cleanup)
    cleanup()
    cmd = ['docker', 'run', '-d', '-p', '5000:5000', '--name', 'dxf_registry']
    # pylint: disable=redefined-outer-name
    regver, _, auth, do_token, _ = request.param
    if auth:
        cmd += ['-v', _registry_dir + ':/registry',
                '-v', _auth_dir + ':/auth']
        if do_token is not None:
            cmd += ['-e', 'REGISTRY_HTTP_TLS_CERTIFICATE=/registry/registry.pem',
                    '-e', 'REGISTRY_HTTP_TLS_KEY=/registry/registry.key']
        if do_token:
            # Thanks to https://the.binbashtheory.com/creating-private-docker-registry-2-0-with-token-authentication-service/
            cmd += ['-e', 'REGISTRY_AUTH=token',
                    '-e', 'REGISTRY_AUTH_TOKEN_REALM=https://localhost:5001/auth',
                    '-e', 'REGISTRY_AUTH_TOKEN_SERVICE=Docker registry',
                    '-e', 'REGISTRY_AUTH_TOKEN_ISSUER=Auth Service',
                    '-e', 'REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/auth/auth.pem']
            cmd2 = ['docker', 'run', '-d', '-p', '5001:5001',
                    '--name', 'dxf_auth', '-v', _auth_dir + ':/auth',
                    'cesanta/docker_auth', '/auth/config.yml']
            subprocess.check_call(cmd2, stdout=DEVNULL)
        else:
            cmd += ['-e', 'REGISTRY_AUTH=htpasswd',
                    '-e', 'REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm',
                    '-e', 'REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd']
    cmd += ['-e', 'REGISTRY_STORAGE_DELETE_ENABLED=true']
    cmd += ['registry:' + str(regver)]
    subprocess.check_call(cmd, stdout=DEVNULL)
    return request.param

_fixture_params = []
for regver in [2, 2.2]:
    for from_base in [False, True]:
        _fixture_params.extend([(regver, from_base, None, False, True),
                                (regver, from_base, _auth_up, None, True),
                                (regver, from_base, _auth_up, False, True),
                                (regver, from_base, _auth_up, True, True),
                                (regver, from_base, _auth_authz, False, True),
                                (regver, from_base, _auth_authz, True, True),
                                (regver, from_base, _auth_authz, True, False)])

@pytest.yield_fixture(scope='module')
def event_loop(request):
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope='module', params=_fixture_params)
async def dxf_obj(request):
    # pylint: disable=redefined-outer-name
    regver, from_base, auth, do_token, tlsverify = _setup_fixture(request)
    tlsverify = os.environ['DXF_TLSVERIFY'] if tlsverify == True else tlsverify

    if from_base:
        base = aiodxf.DXFBase('localhost:5000', auth, (auth is None) or (do_token is None), None, tlsverify)
        r = aiodxf.DXF.from_base(base, pytest.repo)
    else:
        r = aiodxf.DXF('localhost:5000', pytest.repo, auth, (auth is None) or (do_token is None), None, tlsverify)

    r.test_do_auth = auth
    r.test_do_token = do_token
    r.regver = regver
    r.reg_digest = _get_registry_digest(regver)

    async with r:
        for _ in range(5):
            try:
                if do_token is None:
                    with pytest.raises(aiodxf.exceptions.DXFAuthInsecureError):
                        await r.authenticate(pytest.username, pytest.password)
                    yield pytest.skip()
                    return

                assert await r.list_repos() == []

                yield r
                return
            except requests.exceptions.ConnectionError as ex:
                time.sleep(1)
        raise ex

@pytest.fixture(scope='module', params=_fixture_params)
def dxf_main(request):
    # pylint: disable=redefined-outer-name
    regver, from_base, auth, do_token, tlsverify = _setup_fixture(request)
    if from_base:
        return pytest.skip()
    environ = {
        'DXF_HOST': 'localhost:5000',
        'DXF_INSECURE': '1' if ((auth is None) or (do_token is None)) else '0',
        'DXF_SKIPTLSVERIFY': '0' if tlsverify else '1',
        'DXF_TLSVERIFY': os.environ['DXF_TLSVERIFY'],
        'TEST_DO_AUTH': auth,
        'TEST_DO_TOKEN': do_token,
        'REGVER': regver,
        'REG_DIGEST': _get_registry_digest(regver)
    }

    if auth is _auth_up:
        environ['DXF_USERNAME'] = pytest.username
        environ['DXF_PASSWORD'] = pytest.password
    elif auth is _auth_authz:
        environ['DXF_AUTHORIZATION'] = pytest.authorization

    for _ in range(5):
        try:
            if do_token is None:
                with pytest.raises(aiodxf.exceptions.DXFAuthInsecureError):
                    asyncio.run(aiodxf.main.doit(['auth', pytest.repo], environ))
                return pytest.skip()

            assert asyncio.run(aiodxf.main.doit(['list-repos'], environ)) == 0

            return environ
        except requests.exceptions.ConnectionError as ex:
            time.sleep(1)
    raise ex
