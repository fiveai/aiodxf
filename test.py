import asyncio

from aiodxf import DXF

async def auth(dxf, response):
    await dxf.authenticate('fred', 'somepassword', response=response)

async def do():
	dxf = DXF('registry-1.docker.io', 'fred/datalogger', auth)

	dgst = await dxf.push_blob('logger.dat')
	await dxf.set_alias('may15-readings', dgst)

	assert await dxf.get_alias('may15-readings') == [dgst]

	for chunk in await dxf.pull_blob(dgst):
	    sys.stdout.write(chunk)

asyncio.run(do())
