--  Response compression: Content-Encoding: gzip (RFC 9110 8.4), with Sparrow.Gzip.
--
--  The server compresses a response, for HTTP/1.1 and HTTP/2 alike, on the task that ran its handler, when all
--  of these hold:
--
--  - it is a whole response (not a stream or an upgrade) with a 2xx status other than 204 and 206;
--  - its Content-Type is one that shrinks: text/*, JSON, JavaScript, XML, SVG, WebAssembly, and +json or +xml;
--  - it has at least Minimum_Length bytes, and no Content-Encoding of its own;
--  - its Cache-Control does not say no-transform (the way a handler keeps one response as it is);
--  - the client's Accept-Encoding takes gzip;
--  - the result is smaller.
--
--  Such responses get Vary: Accept-Encoding whether or not this client took gzip, so caches keep the two forms
--  apart, and a strong ETag becomes weak (W/"..."): the bytes differ, the content does not. Servers.Configuration's
--  Compression (COMPRESSION=off) turns it all off, for a proxy in front that compresses.
--
--  The gzip header carries 1 to 32 bytes of random padding, so a response's compressed length is a worse guide
--  to its content. That raises the cost of BREACH-style attacks, which guess a secret in a page (a CSRF token)
--  from the lengths of many responses that also echo the attacker's input; it does not end them. Pages that
--  echo request input next to a secret can set Cache-Control: no-transform.
with Sparrow.Http.Requests;
with Sparrow.Http.Responses;

package Sparrow.Http.Compression with SPARK_Mode is

   Minimum_Length : constant := 1024;   --  smaller bodies gain too little to be worth the time

   --  Whether an Accept-Encoding value takes gzip: gzip (or x-gzip) or "*" listed with a weight above zero, an
   --  explicit gzip;q=0 winning over "*".
   function Accepts_Gzip (Accept_Encoding : String) return Boolean;

   --  Whether a Content-Type is one that compresses well.
   function Compressible (Media_Type : String) return Boolean;

   --  The response-only part of the decision: a whole 2xx body of a shrinkable type, long enough, with no
   --  Content-Encoding and no no-transform. Vary: Accept-Encoding must be set before the client is checked.
   function Compressible_Response (Response : Responses.Response) return Boolean
      with Pre => Responses.Valid (Response);

   --  Whether the client takes gzip for a compressible response. The compressor's verdict that the result is
   --  smaller is the only part this cannot decide.
   function Eligible (Request : Requests.Request; Response : Responses.Response) return Boolean
      with Pre => Responses.Valid (Response);

   --  Compress Response for Request if eligible and the compressed bytes are smaller; otherwise leave the body
   --  as it is. Vary: Accept-Encoding may be added either way. The heap compressor pool keeps the body Off;
   --  the full before/after relation cannot be a Post here because 'Old on a by-copy in out parameter is not
   --  allowed in SPARK, so only validity is stated.
   procedure Apply (Request : Requests.Request; Response : in out Responses.Response)
      with Global => null,
           Pre    => Responses.Valid (Response),
           Post   => Responses.Valid (Response);

end Sparrow.Http.Compression;
