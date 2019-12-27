import os
import sys
import errno
import time
import hashlib

import aiohttp
import aiohttp.web
import pytest
import tqdm
import aiodxf.main

# pylint: disable=no-member

@pytest.mark.asyncio
async def test_empty(dxf_main, capsys):
    assert await aiodxf.main.doit(['list-repos'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""

async def _not_found(dxf_main, name):
    assert await aiodxf.main.doit(['blob-size', pytest.repo, name], dxf_main) == errno.ENOENT

@pytest.mark.asyncio
async def test_not_found(dxf_main):
    await _not_found(dxf_main, pytest.blob1_hash)
    await _not_found(dxf_main, pytest.blob2_hash)
    await _not_found(dxf_main, '@fooey')

@pytest.mark.asyncio
async def test_push_blob(dxf_main, capsys):
    assert await aiodxf.main.doit(['push-blob', pytest.repo, pytest.blob1_file], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert await aiodxf.main.doit(['push-blob', pytest.repo, pytest.blob2_file], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + os.linesep
    assert err == ""
    assert await aiodxf.main.doit(['get-alias', pytest.repo, 'fooey'], dxf_main) == errno.ENOENT
    out, err = capsys.readouterr()
    assert out == ""
    assert err.index('Not Found') >= 0
    assert await aiodxf.main.doit(['push-blob', pytest.repo, pytest.blob1_file, '@fooey'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert await aiodxf.main.doit(['get-alias', pytest.repo, 'fooey'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert await aiodxf.main.doit(['list-repos'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.repo + os.linesep
    assert err == ""

async def _pull_blob(dxf_main, name, dgst, capfdbinary):
    assert await aiodxf.main.doit(['pull-blob', pytest.repo, name], dxf_main) == 0
    out, err = capfdbinary.readouterr()
    sha256 = hashlib.sha256()
    sha256.update(out)
    assert 'sha256:' + sha256.hexdigest() == dgst
    assert err == b""

@pytest.mark.asyncio
async def test_pull_blob(dxf_main, capfdbinary):
    environ = {'DXF_BLOB_INFO': '1'}
    environ.update(dxf_main)
    assert await aiodxf.main.doit(['pull-blob', pytest.repo, pytest.blob1_hash, pytest.blob2_hash], environ) == 0
    out, err = capfdbinary.readouterr()
    out_sha256 = hashlib.sha256()
    out_sha256.update(out)
    expected_sha256 = hashlib.sha256()
    expected_sha256.update(pytest.blob1_hash.encode('utf-8'))
    expected_sha256.update(b' ')
    expected_sha256.update(str(pytest.blob1_size).encode('utf-8'))
    expected_sha256.update(os.linesep.encode('utf-8'))
    with open(pytest.blob1_file, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            expected_sha256.update(chunk)
    expected_sha256.update(pytest.blob2_hash.encode('utf-8'))
    expected_sha256.update(b' ')
    expected_sha256.update(str(pytest.blob2_size).encode('utf-8'))
    expected_sha256.update(os.linesep.encode('utf-8'))
    with open(pytest.blob2_file, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            expected_sha256.update(chunk)
    assert out_sha256.digest() == expected_sha256.digest()
    assert err == b""
    await _pull_blob(dxf_main, pytest.blob1_hash, pytest.blob1_hash, capfdbinary)
    await _pull_blob(dxf_main, pytest.blob2_hash, pytest.blob2_hash, capfdbinary)
    await _pull_blob(dxf_main, '@fooey', pytest.blob1_hash, capfdbinary)

@pytest.mark.asyncio
async def test_progress(dxf_main, capfd):
    environ = {'DXF_PROGRESS': '1'}
    environ.update(dxf_main)
    assert await aiodxf.main.doit(['pull-blob', pytest.repo, pytest.blob1_hash], environ) == 0
    _, err = capfd.readouterr()
    assert pytest.blob1_hash[0:8] in err
    assert " 0%" in err
    assert " 100%" in err
    assert " " + str(pytest.blob1_size) + "/" + str(pytest.blob1_size) in err
    assert await aiodxf.main.doit(['push-blob', pytest.repo, pytest.blob3_file], environ) == 0
    _, err = capfd.readouterr()
    assert pytest.blob3_hash[0:8] in err
    assert " 0%" in err
    assert " 100%" in err
    assert " " + str(pytest.blob3_size) + "/" + str(pytest.blob3_size) in err

@pytest.mark.asyncio
async def test_see_progress(dxf_main, monkeypatch):
    environ = {'DXF_PROGRESS': '1'}
    environ.update(dxf_main)
    # pylint: disable=too-few-public-methods
    class FakeStdout(object):
        # pylint: disable=no-self-use
        def write(self, _):
            time.sleep(0.05)
    monkeypatch.setattr(sys, 'stdout', FakeStdout())
    assert await aiodxf.main.doit(['pull-blob', pytest.repo, pytest.blob1_hash], environ) == 0
    orig_tqdm = tqdm.tqdm
    def new_tqdm(*args, **kwargs):
        tqdm_obj = orig_tqdm(*args, **kwargs)
        class TQDM(object):
            # pylint: disable=no-self-use
            def update(self, n):
                tqdm_obj.update(n)
                time.sleep(0.025)
            def close(self):
                tqdm_obj.close()
            @property
            def n(self):
                return tqdm_obj.n
            @property
            def total(self):
                return tqdm_obj.total
        return TQDM()
    monkeypatch.setattr(tqdm, 'tqdm', new_tqdm)
    assert await aiodxf.main.doit(['push-blob', pytest.repo, pytest.blob4_file], environ) == 0

@pytest.mark.asyncio
async def test_set_alias(dxf_main, capsys):
    assert await aiodxf.main.doit(['set-alias', pytest.repo, 'hello', pytest.blob1_hash], dxf_main) == 0
    _, err = capsys.readouterr()
    assert err == ""
    if dxf_main['REGVER'] != 2.2:
        assert await aiodxf.main.doit(['del-alias', pytest.repo, 'hello'], dxf_main) == 0
        out, err = capsys.readouterr()
        assert out == pytest.blob1_hash + os.linesep
        assert err == ""
        # Deleting tag actually deletes by DCD:
        # https://github.com/docker/distribution/issues/1566
        # So fooey gets deleted too
        assert await aiodxf.main.doit(['list-aliases', pytest.repo], dxf_main) == 0
        out, err = capsys.readouterr()
        assert out == ""
        assert err == ""
        assert await aiodxf.main.doit(['set-alias', pytest.repo, 'hello', pytest.blob1_hash], dxf_main) == 0
        assert await aiodxf.main.doit(['set-alias', pytest.repo, 'fooey', pytest.blob1_hash], dxf_main) == 0
        _, err = capsys.readouterr()
        assert err == ""
    assert await aiodxf.main.doit(['set-alias', pytest.repo, 'there', pytest.blob1_hash, pytest.blob2_hash], dxf_main) == 0
    _, err = capsys.readouterr()
    assert err == ""
    assert await aiodxf.main.doit(['set-alias', pytest.repo, 'world', pytest.blob2_file], dxf_main) == 0
    _, err = capsys.readouterr()
    assert err == ""

@pytest.mark.asyncio
async def test_get_alias(dxf_main, capsys):
    assert await aiodxf.main.doit(['get-alias', pytest.repo, 'hello'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert await aiodxf.main.doit(['get-alias', pytest.repo, 'there'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep + \
                  pytest.blob2_hash + os.linesep
    assert err == ""
    assert await aiodxf.main.doit(['get-alias', pytest.repo, 'world'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + os.linesep
    assert err == ""

@pytest.mark.asyncio
async def test_get_digest(dxf_main, capsys):
    if dxf_main['REGVER'] == 2.2:
        with pytest.raises(aiodxf.exceptions.DXFDigestNotAvailableForSchema1):
            await aiodxf.main.doit(['get-image-id', pytest.repo, 'hello'], dxf_main)
        return
    assert await aiodxf.main.doit(['get-image-id', pytest.repo, 'hello'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert await aiodxf.main.doit(['get-image-id', pytest.repo, 'there'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert await aiodxf.main.doit(['get-image-id', pytest.repo, 'world'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + os.linesep
    assert err == ""
    pytest.copy_registry_image(dxf_main['REGVER'])
    assert await aiodxf.main.doit(['get-image-id',
                          'test/registry',
                          str(dxf_main['REGVER'])],
                         dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == dxf_main['REG_DIGEST'] + os.linesep
    assert err == ""

@pytest.mark.asyncio
async def test_blob_size(dxf_main, capsys):
    assert await aiodxf.main.doit(['blob-size', pytest.repo, pytest.blob1_hash, pytest.blob2_hash, '@hello', '@there', '@world'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == str(pytest.blob1_size) + os.linesep + \
                  str(pytest.blob2_size) + os.linesep + \
                  str(pytest.blob1_size) + os.linesep + \
                  str(pytest.blob1_size + pytest.blob2_size) + os.linesep + \
                  str(pytest.blob2_size) + os.linesep
    assert err == ""

@pytest.mark.asyncio
async def test_list_aliases(dxf_main, capsys):
    assert await aiodxf.main.doit(['list-aliases', pytest.repo], dxf_main) == 0
    out, err = capsys.readouterr()
    assert sorted(out.split(os.linesep)) == ['', 'fooey', 'hello', 'there', 'world']
    assert err == ""

@pytest.mark.asyncio
async def test_manifest(dxf_main, capfdbinary, monkeypatch):
    assert await aiodxf.main.doit(['set-alias', pytest.repo, 'mani_test', pytest.blob1_hash], dxf_main) == 0
    manifest, err = capfdbinary.readouterr()
    assert manifest
    assert err == b""
    # pylint: disable=too-few-public-methods
    class FakeStdin(object):
        # pylint: disable=no-self-use
        def read(self):
            return manifest.decode()
    monkeypatch.setattr(sys, 'stdin', FakeStdin())
    assert await aiodxf.main.doit(['get-alias', pytest.repo], dxf_main) == 0
    out, err = capfdbinary.readouterr()
    assert out.decode() == pytest.blob1_hash + os.linesep
    assert err == b""
    assert await aiodxf.main.doit(['blob-size', pytest.repo], dxf_main) == 0
    out, err = capfdbinary.readouterr()
    assert out.decode() == str(pytest.blob1_size) + os.linesep
    assert err == b""
    assert await aiodxf.main.doit(['pull-blob', pytest.repo], dxf_main) == 0
    out, err = capfdbinary.readouterr()
    sha256 = hashlib.sha256()
    sha256.update(out)
    assert 'sha256:' + sha256.hexdigest() == pytest.blob1_hash
    assert err == b""
    assert await aiodxf.main.doit(['del-blob', pytest.repo], dxf_main) == 0
    assert await aiodxf.main.doit(['pull-blob', pytest.repo], dxf_main) == errno.ENOENT

#@pytest.mark.onlytest
@pytest.mark.asyncio
async def test_auth(dxf_main, capsys):
    if (not dxf_main['TEST_DO_AUTH']) or (not dxf_main['TEST_DO_TOKEN']):
        assert await aiodxf.main.doit(['auth', pytest.repo], dxf_main) == 0
        out, err = capsys.readouterr()
        assert out == ""
        assert err == ""
    else:
        assert await aiodxf.main.doit(['auth', pytest.repo, '*'], dxf_main) == 0
        token, err = capsys.readouterr()
        assert token
        assert err == ""
        environ = {}
        environ.update(dxf_main)
        environ.pop('DXF_USERNAME', None)
        environ.pop('DXF_PASSWORD', None)
        environ.pop('DXF_AUTHORIZATION', None)
        assert await aiodxf.main.doit(['list-repos'], environ) == 0
        out, err = capsys.readouterr()
        expected = [pytest.repo]
        if dxf_main['REGVER'] != 2.2:
            expected += ['test/registry']
        assert sorted(out.rstrip().split(os.linesep)) == sorted(expected)
        assert err == ""
        assert await aiodxf.main.doit(['list-aliases', pytest.repo], environ) == errno.EACCES
        out, err = capsys.readouterr()
        assert out == ""
        environ['DXF_TOKEN'] = token.strip()
        assert await aiodxf.main.doit(['list-aliases', pytest.repo], environ) == 0
        out, err = capsys.readouterr()
        assert sorted(out.split(os.linesep)) == ['', 'fooey', 'hello', 'mani_test', 'there', 'world']
        assert err == ""

@pytest.mark.asyncio
async def test_del_blob(dxf_main, capfdbinary):
    await _pull_blob(dxf_main, pytest.blob2_hash, pytest.blob2_hash, capfdbinary)
    assert await aiodxf.main.doit(['del-blob', pytest.repo, pytest.blob2_hash], dxf_main) == 0
    await _not_found(dxf_main, pytest.blob2_hash)
    assert await aiodxf.main.doit(['del-blob', pytest.repo, pytest.blob2_hash], dxf_main) == errno.ENOENT

@pytest.mark.asyncio
async def test_del_alias(dxf_main, capsys):
    assert await aiodxf.main.doit(['get-alias', pytest.repo, 'world'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + os.linesep
    assert err == ""
    if dxf_main['REGVER'] == 2.2:
        with pytest.raises(aiohttp.ClientResponseError) as ex:
            await aiodxf.main.doit(['del-alias', pytest.repo, 'world'], dxf_main)
        assert ex.value.status == aiohttp.web.HTTPMethodNotAllowed.status_code
        assert await aiodxf.main.doit(['get-alias', pytest.repo, 'world'], dxf_main) == 0
    else:
        assert await aiodxf.main.doit(['del-alias', pytest.repo, 'world'], dxf_main) == 0
        out, err = capsys.readouterr()
        assert out == pytest.blob2_hash + os.linesep
        # Note: test gc but it isn't needed to make a 404
        pytest.gc()
        assert await aiodxf.main.doit(['get-alias', pytest.repo, 'world'], dxf_main) == errno.ENOENT
        assert await aiodxf.main.doit(['del-alias', pytest.repo, 'world'], dxf_main) == errno.ENOENT

async def _num_args(dxf_main, op, minimum, maximum, capsys):
    if minimum is not None:
        with pytest.raises(SystemExit):
            await aiodxf.main.doit([op, pytest.repo] + ['a'] * (minimum - 1), dxf_main)
        out, err = capsys.readouterr()
        assert out == ""
        assert "too few arguments" in err
    if maximum is not None:
        with pytest.raises(SystemExit):
            await aiodxf.main.doit([op, pytest.repo] + ['a'] * (maximum + 1), dxf_main)
        out, err = capsys.readouterr()
        assert out == ""
        assert "too many arguments" in err

@pytest.mark.asyncio
async def test_bad_args(dxf_main, capsys):
    await _num_args(dxf_main, 'push-blob', 1, 2, capsys)
    await _num_args(dxf_main, 'set-alias', 2, None, capsys)
    await _num_args(dxf_main, 'list-aliases', None, 0, capsys)
    with pytest.raises(SystemExit):
        await aiodxf.main.doit(['push-blob', pytest.repo, pytest.blob1_file, 'fooey'], dxf_main)
    out, err = capsys.readouterr()
    assert out == ""
    assert "invalid alias" in err

@pytest.mark.asyncio
async def test_auth_host(dxf_main):
    if dxf_main['TEST_DO_TOKEN']:
        environ = {
            'DXF_AUTH_HOST': 'localhost:5002'
        }
        environ.update(dxf_main)
        with pytest.raises(aiohttp.ClientConnectionError):
            await aiodxf.main.doit(['list-repos'], environ)

@pytest.mark.asyncio
async def test_tlsverify(dxf_main):
    if dxf_main['DXF_INSECURE'] == '0':
        verify = dxf_main['DXF_TLSVERIFY']
        del dxf_main['DXF_TLSVERIFY']
        try:
            if dxf_main['DXF_SKIPTLSVERIFY'] == '0':
                with pytest.raises(aiohttp.ClientSSLError):
                    await aiodxf.main.doit(['list-repos'], dxf_main)
            else:
                assert await aiodxf.main.doit(['list-repos'], dxf_main) == 0
        finally:
            dxf_main['DXF_TLSVERIFY'] = verify

@pytest.mark.asyncio
async def test_tlsverify_str(dxf_main):
    if dxf_main['DXF_INSECURE'] == '0':
        skip = dxf_main['DXF_SKIPTLSVERIFY']
        dxf_main['DXF_SKIPTLSVERIFY'] = '0'
        try:
            assert await aiodxf.main.doit(['list-repos'], dxf_main) == 0
        finally:
            dxf_main['DXF_SKIPTLSVERIFY'] = skip
