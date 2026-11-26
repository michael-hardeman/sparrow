# sparrow_core

The root package `Sparrow` and the pieces every other Sparrow crate shares: byte buffers, checked text
conversions, time formats, Base64, gzip, the migration steps both database crates apply, and the interfaces of shared stores. Pure Ada, no
dependencies; everything but `Migrations` and `Stores` is proved free of run-time errors (SPARK silver).

```toml
[[depends-on]]
sparrow_core = "~1.0.0"
```

## Packages

| Package | What it does |
|---|---|
| `Sparrow` | `UTF8_String`, a type of its own, distinct from `String` (bytes) |
| `Sparrow.Buffers` | `Buffer`: a growable byte buffer that every crate reads into and writes into |
| `Sparrow.Encoding` | Checked bytes ↔ `UTF8_String` conversions, spans, decimal numbers, case-insensitive comparison, percent-decoding, query values |
| `Sparrow.Times` | Unix seconds and microseconds, RFC 3339 and HTTP dates |
| `Sparrow.Base64` | RFC 4648, standard (padded) and URL-safe (unpadded) |
| `Sparrow.Migrations` | Schema migration steps (version and SQL), applied by `sparrow_sqlite` and `sparrow_postgres` |
| `Sparrow.Deflate` | DEFLATE compression (RFC 1951): LZ77 with hash chains and lazy matching, then each block as the smallest of dynamic Huffman, fixed Huffman or stored |
| `Sparrow.Gzip` | gzip (RFC 1952) around it, and CRC-32 |
| `Sparrow.Stores` | Interfaces for state kept outside the server: `Session_Table` (sessions) and `Bucket_Store` (rate limits). `sparrow_http` uses them, `sparrow_valkey` implements them, and neither depends on the other |

## Conventions

- **Bytes are `String`, text is `UTF8_String`.** Whatever arrives from a socket is bytes. It becomes text only
  through a checked conversion, so unchecked input cannot reach a JSON writer, a template or an SQL text
  parameter by accident.
  ```ada
  if Encoding.Valid_Utf8 (Raw) then
     Title := Encoding.To_UTF8 (Raw);
  end if;
  ```
- **Parsers are total.** Bad input gives `Valid = False` (or a neutral value), never an exception.
- **Appends are total.** A buffer past `Max_Capacity` stops growing and is marked `Overflowed`.
- Results are indexed from 1.

## Buffers

```ada
Page : Buffer;
...
Append (Page, "<h1>");
Append_Text (Page, Title);          --  UTF8_String
Append (Page, "</h1>");
Send (Socket, Content (Page), ...);
Free (Page);
```

`Reserve`, `Consume` (drop bytes from the front) and `Truncate` make a buffer usable as an input queue;
`Append_Big_Endian` and `Overwrite_Big_Endian` serve wire protocols.

## Times and Base64

```ada
Times.Rfc3339 (Now)        --  "2026-11-17T14:21:55.123Z"
Times.Http_Date (Seconds)  --  "Tue, 17 Nov 2026 14:21:55 GMT"
Base64.Encode (Key, Using => Base64.Url_Safe)
```

## Compression

```ada
Work : constant access Deflate.State := new Deflate.State;   --  about 200 KiB: one per task, reused
...
Gzip.Compress (Work.all, Page, Output, Last, Fits);           --  Output (Output'First .. Last), when Fits
```

Give `Output` only as much room as the result is worth: when the result does not fit, `Fits` is False, and
input that does not shrink stops costing time once it has filled that room. On text, the output is about 5%
larger than `gzip -6` and is produced faster, at about 75 MB/s per core. Compression only; there is no
decoder. sparrow_http uses it for `Content-Encoding: gzip`.

## Proof

```sh
alr exec -- gnatprove -P sparrow_core.gpr -j0 --mode=silver --level=4 --prover=cvc5,z3 --steps=200000 --timeout=300
```

Everything here is proved free of run-time errors, the compressor included. Its output is also checked
against zlib's decoder in the tests and under fuzzing (`tests/fuzz`, target `compression`).

MIT licensed.
