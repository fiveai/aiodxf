import os
import hashlib
import json
import pytest
from jwcrypto import jws
import aiodxf.exceptions
import aiohttp.web

# pylint: disable=no-member

async def _not_found(dxf_obj, dgst):
    with pytest.raises(aiohttp.ClientResponseError) as ex:
        await dxf_obj.blob_size(dgst)
    assert ex.value.status == aiohttp.web.HTTPNotFound.status_code

@pytest.mark.asyncio
async def test_not_found(dxf_obj):
    await _not_found(dxf_obj, pytest.blob1_hash)
    await _not_found(dxf_obj, pytest.blob2_hash)

@pytest.mark.asyncio
async def test_api_version_check(dxf_obj):
    await dxf_obj.api_version_check()

@pytest.mark.asyncio
async def test_push_blob(dxf_obj):
    assert await dxf_obj.push_blob(pytest.blob1_file) == pytest.blob1_hash
    state = {
        'called': False,
        'total': 0
    }
    # pylint: disable=unused-argument
    def progress1(dgst, chunk, size):
        state['called'] = True
    assert await dxf_obj.push_blob(pytest.blob1_file, progress=progress1) == pytest.blob1_hash
    assert not state['called']
    def progress2(dgst, chunk, size):
        assert size == pytest.blob2_size
        state['total'] += len(chunk)
    assert await dxf_obj.push_blob(pytest.blob2_file, progress=progress2) == pytest.blob2_hash
    assert state['total'] == pytest.blob2_size
    assert await dxf_obj.list_repos() == [pytest.repo]

@pytest.mark.asyncio
async def test_blob_size(dxf_obj):
    assert await dxf_obj.blob_size(pytest.blob1_hash) == pytest.blob1_size
    assert await dxf_obj.blob_size(pytest.blob2_hash) == pytest.blob2_size

async def _pull_blob(dxf_obj, dgst, expected_size, chunk_size):
    if expected_size is None:
        stream = await dxf_obj.pull_blob(dgst)
    else:
        stream, size = await dxf_obj.pull_blob(dgst, size=True)
        assert size == expected_size
    sha256 = hashlib.sha256()
    async for chunk in stream.iter_chunked(chunk_size or 8192):
        sha256.update(chunk)
    assert 'sha256:' + sha256.hexdigest() == dgst

@pytest.mark.asyncio
async def test_pull_blob(dxf_obj):
    await _pull_blob(dxf_obj, pytest.blob1_hash, None, None)
    await _pull_blob(dxf_obj, pytest.blob2_hash, pytest.blob2_size, None)
    await _pull_blob(dxf_obj, pytest.blob1_hash, None, 4096)
    with pytest.raises(aiodxf.exceptions.DXFDigestMismatchError) as ex:
        class DummySHA256(object):
            # pylint: disable=no-self-use
            def update(self, chunk):
                pass
            def hexdigest(self):
                return orig_sha256().hexdigest()
        orig_sha256 = hashlib.sha256
        hashlib.sha256 = DummySHA256
        try:
            stream = await dxf_obj.pull_blob(pytest.blob1_hash)
            async for _ in stream.iter_any():
                pass
        finally:
            hashlib.sha256 = orig_sha256
    assert ex.value.got == 'sha256:' + hashlib.sha256().hexdigest()
    assert ex.value.expected == pytest.blob1_hash

@pytest.mark.asyncio
async def test_pull_and_push_blob(dxf_obj):
    stream = await dxf_obj.pull_blob(pytest.blob1_hash)
    state = {'total': 0}
    sha256 = hashlib.sha256()
    def progress(dgst, chunk):
        assert dgst == pytest.blob1_hash
        state['total'] += len(chunk)
        sha256.update(chunk)
    assert await dxf_obj.push_blob(data=stream,
                             digest=pytest.blob1_hash,
                             progress=progress,
                             check_exists=False) == \
           pytest.blob1_hash
    assert state['total'] == pytest.blob1_size
    assert 'sha256:' + sha256.hexdigest() == pytest.blob1_hash
    await _pull_blob(dxf_obj, pytest.blob1_hash, pytest.blob1_size, None)

@pytest.mark.asyncio
async def test_set_alias(dxf_obj):
    await dxf_obj.set_alias('hello', pytest.blob1_hash)
    if dxf_obj.regver != 2.2:
        assert await dxf_obj.del_alias('hello') == [pytest.blob1_hash]
        assert await dxf_obj.list_aliases() == []
        await dxf_obj.set_alias('hello', pytest.blob1_hash)
    await dxf_obj.set_alias('there', pytest.blob1_hash, pytest.blob2_hash)
    await dxf_obj.set_alias('world', pytest.blob2_hash)

@pytest.mark.asyncio
async def test_get_alias(dxf_obj):
    assert await dxf_obj.get_alias('hello') == [pytest.blob1_hash]
    assert await dxf_obj.get_alias('there') == [pytest.blob1_hash, pytest.blob2_hash]
    assert await dxf_obj.get_alias('world') == [pytest.blob2_hash]

@pytest.mark.asyncio
async def test_get_image_id(dxf_obj):
    if dxf_obj.regver == 2.2:
        with pytest.raises(aiodxf.exceptions.DXFDigestNotAvailableForSchema1):
            await dxf_obj.get_image_id('hello')
        return
    assert await dxf_obj.get_image_id('hello') == pytest.blob1_hash
    assert await dxf_obj.get_image_id('there') == pytest.blob1_hash
    assert await dxf_obj.get_image_id('world') == pytest.blob2_hash
    pytest.copy_registry_image(dxf_obj.regver)
    # pylint: disable=protected-access
    dxf_obj2 = aiodxf.DXF('localhost:5000', 'test/registry', dxf_obj._auth, dxf_obj._insecure, None, dxf_obj._tlsverify)
    async with dxf_obj2:
        assert await dxf_obj2.get_image_id(str(dxf_obj.regver)) == dxf_obj.reg_digest

@pytest.mark.asyncio
async def test_list_aliases(dxf_obj):
    assert sorted(await dxf_obj.list_aliases()) == ['hello', 'there', 'world']
    assert sorted([x async for x in await dxf_obj.list_aliases(batch_size=2, iterate=True)]) == ['hello', 'there', 'world']

@pytest.mark.asyncio
async def test_context_manager(dxf_obj):
    async with dxf_obj as odxf:
        await test_list_aliases(odxf)

@pytest.mark.asyncio
async def test_manifest(dxf_obj):
    manifest = await dxf_obj.set_alias('mani_test', pytest.blob1_hash)
    assert manifest
    if dxf_obj.regver != 2.2:
        assert await dxf_obj.get_manifest('mani_test') == manifest
    #assert json.dumps(json.loads(dxf_obj.get_manifest('mani_test')),
    #                  sort_keys=True) == \
    #       json.dumps(json.loads(manifest), sort_keys=True)
    assert await dxf_obj.get_alias(manifest=manifest) == [pytest.blob1_hash]
    if json.loads(manifest)['schemaVersion'] == 1:
        with pytest.raises(jws.InvalidJWSSignature):
            await dxf_obj.get_alias(manifest=' '+manifest)
    if dxf_obj.regver != 2.2:
        await dxf_obj.set_manifest('mani_test2', manifest)
        assert await dxf_obj.get_alias('mani_test2') == [pytest.blob1_hash]

@pytest.mark.asyncio
async def test_unsigned_manifest_v1(dxf_obj):
    manifest = dxf_obj.make_unsigned_manifest('mani_test3', pytest.blob2_hash)
    assert manifest
    with pytest.raises(KeyError):
        await dxf_obj.get_alias(manifest=manifest)
    assert await dxf_obj.get_alias(manifest=manifest, verify=False) == [pytest.blob2_hash]

@pytest.mark.asyncio
async def test_unsigned_manifest_v2(dxf_obj):
    manifest = await dxf_obj.make_manifest(pytest.blob2_hash)
    assert manifest
    assert await dxf_obj.get_alias(manifest=manifest) == [pytest.blob2_hash]

#@pytest.mark.onlytest
@pytest.mark.asyncio
async def test_auth(dxf_obj):
    # pylint: disable=protected-access
    if not dxf_obj.test_do_auth:
        assert await dxf_obj.authenticate() is None
    elif not dxf_obj.test_do_token:
        assert await dxf_obj.authenticate(pytest.username, pytest.password) is None
    else:
        assert await dxf_obj.authenticate(pytest.username, pytest.password, '*') == dxf_obj.token
        assert dxf_obj.token

@pytest.mark.asyncio
async def test_del_blob(dxf_obj):
    await _pull_blob(dxf_obj, pytest.blob2_hash, None, None)
    await dxf_obj.del_blob(pytest.blob2_hash)
    await _not_found(dxf_obj, pytest.blob2_hash)
    with pytest.raises(aiohttp.ClientResponseError) as ex:
        await dxf_obj.del_blob(pytest.blob2_hash)
    assert ex.value.status == aiohttp.web.HTTPNotFound.status_code

@pytest.mark.asyncio
async def test_del_alias(dxf_obj):
    assert await dxf_obj.get_alias('world') == [pytest.blob2_hash]
    if dxf_obj.regver == 2.2:
        with pytest.raises(aiohttp.ClientResponseError) as ex:
            await dxf_obj.del_alias('world')
        assert ex.value.status == aiohttp.web.HTTPMethodNotAllowed.status_code
        assert await dxf_obj.get_alias('world') == [pytest.blob2_hash]
    else:
        assert await dxf_obj.del_alias('world') == [pytest.blob2_hash]
        # Note: test gc but it isn't needed to make a 404
        pytest.gc()
        with pytest.raises(aiohttp.ClientResponseError) as ex:
            await dxf_obj.get_alias('world')
        assert ex.value.status == aiohttp.web.HTTPNotFound.status_code
        with pytest.raises(aiohttp.ClientResponseError) as ex:
            await dxf_obj.del_alias('world')
        assert ex.value.status == aiohttp.web.HTTPNotFound.status_code

_abc_hash = 'sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

def test_hash_bytes():
    assert aiodxf.hash_bytes(b'abc') == _abc_hash

@pytest.mark.asyncio
async def test_tlsverify(dxf_obj):
    # pylint: disable=protected-access
    if not dxf_obj._insecure:
        if dxf_obj._tlsverify is None:
            with pytest.raises(aiohttp.ClientSSLError):
                await dxf_obj.list_repos()
        else:
            expected = [pytest.repo]
            if dxf_obj.regver != 2.2:
                expected += ['test/registry']
            assert sorted(await dxf_obj.list_repos()) == sorted(expected)

@pytest.mark.asyncio
async def test_tlsverify_str(dxf_obj):
    # pylint: disable=protected-access
    if not dxf_obj._insecure:
        expected = [pytest.repo]
        if dxf_obj.regver != 2.2:
            expected += ['test/registry']
        assert sorted(await dxf_obj.list_repos()) == sorted(expected)

@pytest.mark.asyncio
async def test_pagination(dxf_obj):
    # pylint: disable=protected-access
    num = 11
    for i in range(num):
        name = 'test/{0}'.format(i)
        dxf_obj2 = aiodxf.DXF('localhost:5000', name, dxf_obj._auth, dxf_obj._insecure, None, dxf_obj._tlsverify)
        async with dxf_obj2:
            assert await dxf_obj2.push_blob(data=b'abc', digest=_abc_hash) == _abc_hash
    expected = [pytest.repo] + ['test/{0}'.format(i) for i in range(num)]
    if dxf_obj.regver != 2.2:
        expected += ['test/registry']
    async with dxf_obj2:
        assert sorted(await dxf_obj2.list_repos(batch_size=3)) == sorted(expected)
