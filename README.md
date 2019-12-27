# aiodxf

asyncio port of [dxf](https://github.com/davedoesdev/dxf)

## Usage

The `aiodxf` command-line tool uses the following environment variables:

- `DXF_HOST` - Host where Docker registry is running.
- `DXF_INSECURE` - Set this to `1` if you want to connect to the registry using
   `http` rather than `https` (which is the default).
- `DXF_USERNAME` - Name of user to authenticate as.
- `DXF_PASSWORD` - User's password.
- `DXF_AUTHORIZATION` - HTTP `Authorization` header value.
- `DXF_AUTH_HOST` - If set, always perform token authentication to this host, overriding the value returned by the registry.
- `DXF_PROGRESS` - If this is set to `1`, a progress bar is displayed (on standard error) during `push-blob` and `pull-blob`. If this is set to `0`, a progress bar is not displayed. If this is set to any other value, a progress bar is only displayed if standard error is a terminal.
- `DXF_BLOB_INFO` - Set this to `1` if you want `pull-blob` to prepend each blob with its digest and size (printed in plain text, separated by a space and followed by a newline).
- `DXF_CHUNK_SIZE` - Number of bytes `pull-blob` should download at a time. Defaults to 8192.
- `DXF_SKIPTLSVERIFY` - Set this to `1` to skip TLS certificate verification.
- `DXF_TLSVERIFY` - Optional path to custom CA bundle to use for TLS verification.

You can use the following options with `dxf`. Supply the name of the repository
you wish to work with in each case as the second argument.

-   `aiodxf push-blob <repo> <file> [@alias]`

    > Upload a file to the registry and optionally give it a name (alias).
    > The blob's hash is printed to standard output.

    > The hash or the alias can be used to fetch the blob later using
    > `pull-blob`.

-   `aiodxf pull-blob <repo> <hash>|<@alias>...`

    > Download blobs from the registry to standard output. For each blob you
    > can specify its hash, prefixed by `sha256:` (remember the registry is
    > content-addressable) or an alias you've given it (using `push-blob` or
    > `set-alias`).

-   `aiodxf blob-size <repo> <hash>|<@alias>...`

    > Print the size of blobs in the registry. If you specify an alias, the
    > sum of all the blobs it points to will be printed.

-   `aiodxf del-blob <repo> <hash>|<@alias>...`

    > Delete blobs from the registry. If you specify an alias the blobs it
    > points to will be deleted, not the alias itself. Use `del-alias` for that.

-   `aiodxf set-alias <repo> <alias> <hash>|<file>...`

    > Give a name (alias) to a set of blobs. For each blob you can either
    > specify its hash (as printed by `get-blob`) or, if you have the blob's
    > contents on disk, its filename (including a path separator to
    > distinguish it from a hash).

-   `aiodxf get-alias <repo> <alias>...`

    > For each alias you specify, print the hashes of all the blobs it points
    > to.

-   `aiodxf del-alias <repo> <alias>...`

    > Delete each specified alias. The blobs they point to won't be deleted
    > (use `del-blob` for that), but their hashes will be printed.

-   `aiodxf list-aliases <repo>`

    > Print all the aliases defined in the repository.

-   `aiodxf list-repos`

    > Print the names of all the repositories in the registry. Not all versions
    > of the registry support this.

-   `aiodxf get-digest <repo> <alias>...`

    > For each alias you specify, print the hash of its configuration blob.
    > For an alias created using `dxf`, this is the hash of the first blob it
    > points to. For a Docker image tag, this is the same as
    > `docker inspect alias --format='{{.Id}}'`.

## Certificates

If your registry uses SSL with a self-issued certificate, you'll need to supply
`dxf` with a set of trusted certificate authorities.

You can set the `DXF_TLSVERIFY` environment variable to the path of a PEM file
containing the trusted certificate authority certificates for the command-line
tool or pass the `tlsverify` option to the module.

## Authentication tokens

`dxf` automatically obtains Docker registry authentication tokens using your
`DXF_USERNAME` and `DXF_PASSWORD`, or `DXF_AUTHORIZATION`, environment variables
as necessary.

However, if you wish to override this then you can use the following command:

-   `aiodxf auth <repo> <action>...`

    > Authenticate to the registry using `DXF_USERNAME` and `DXF_PASSWORD`,
    > or `DXF_AUTHORIZATION`, and print the resulting token.

    > `action` can be `pull`, `push` or `*`.

If you assign the token to the `DXF_TOKEN` environment variable, for example:

`DXF_TOKEN=$(aiodxf auth fred/datalogger pull)`

then subsequent `dxf` commands will use the token without needing
`DXF_USERNAME` and `DXF_PASSWORD`, or `DXF_AUTHORIZATION`, to be set.

Note however that the token expires after a few minutes, after which `dxf` will
exit with `EACCES`.


## Installation

```shell
pip install aiodxf
```

## Licence

[MIT](https://raw.github.com/fiveai/aiodxf/master/LICENCE)

## Tests

```shell
make test
```

## Lint

```shell
make lint
```

## Code Coverage

```shell
make coverage
```
