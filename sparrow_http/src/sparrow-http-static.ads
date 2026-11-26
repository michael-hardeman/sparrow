--  Files from a folder: the media type from the extension, an ETag and Last-Modified from the file, 304 for a
--  matching If-None-Match, index.html for a directory.
--
--  Ranges: a Range of bytes is answered 206 with just those bytes (If-Range respected), one past the end 416;
--  players seek in videos and downloads resume. Compression: when the client takes gzip and a file.gz is
--  beside the file (made ahead, with gzip -9 or zopfli), that is sent as it is; otherwise the server compresses
--  text files as it does any response (Sparrow.Http.Compression).
--
--  The short way, one route:
--
--     Routers.Add (Routes, Get, "/static/*file", Static.Folder ("public", Max_Age => 3600));
--
--  Requests that try to leave the folder ("..", an absolute path, a drive letter, a backslash) and hidden
--  names (any segment starting with '.') are answered 404, never read. Reading a file blocks: route the
--  handler On_Worker (the default).
with Sparrow.Buffers;
with Sparrow.Http.Requests;
with Sparrow.Http.Responses;
with Sparrow.Http.Routers;

package Sparrow.Http.Static with SPARK_Mode is

   --  "text/css; charset=utf-8" for "site.css"; application/octet-stream for an unknown extension.
   function Media_Type_Of (File_Name : String) return String;

   --  Whether Relative (decoded, '/'-separated) names something inside a folder: not absolute, no empty,
   --  "." or ".." segment, no hidden segment, no '\', ':', NUL or other control byte.
   function Is_Safe_Path (Relative : String) return Boolean;

   --  Answer with the file Root/Relative: 200 with its bytes (headers only for HEAD), 206 with part of them for a
   --  Range, 416 for a Range past its end, 304 when the client's copy is current, 404 when it is missing or
   --  Relative is not safe, 301 to the path with a '/' for a directory requested without one. Relative "" or
   --  ending in '/' means its index.html. Max_Age is the Cache-Control max-age in seconds; 0 makes clients
   --  revalidate every time (still cheap: a 304).
   procedure Serve_File
     (Request  : Requests.Request;
      Response : in out Responses.Response;
      Root     : String;
      Relative : String;
      Max_Age  : Natural := 0)
      with Pre  => Responses.Valid (Response),
           Post => Responses.Valid (Response)
                   and then
                     (if ((Relative'Length = 0 or else Relative (Relative'Last) = '/')
                          and then Relative'Last < Positive'Last
                          and then not Is_Safe_Path (Relative & "index.html"))
                       or else (Relative'Length > 0
                                and then Relative (Relative'Last) /= '/'
                                and then not Is_Safe_Path (Relative))
                      then Response.Status = Not_Found);

   --  Largest file served whole; past it, 404 (stream big files from a CDN or a front proxy). Larger files are
   --  still served in ranges, up to this many bytes per response.
   Max_File_Size : constant := 64 * 1024 * 1024;

   --  The route holds heap strings and has dispatching primitives, both outside SPARK; the hostile path check
   --  and Serve_File above remain proved.
   package Routes with SPARK_Mode => Off is
      --  A folder as a route's handler: Serve_File with the route's "*" capture as Relative.
      type Folder_Route is new Routers.Route_Handler with private;

      overriding procedure Handle
        (This : Folder_Route; Request : Requests.Request; Response : in out Responses.Response);

      function Make (Root : String; Capture : String; Max_Age : Natural) return Folder_Route;
   private
      type Folder_Route is new Routers.Route_Handler with record
         Root    : Sparrow.Buffers.String_Access;
         Capture : Sparrow.Buffers.String_Access;
         Max_Age : Natural := 0;
      end record;
   end Routes;

   --  Root: the folder, absolute or relative to the working directory. Capture: the name of the route's "*"
   --  capture.
   function Folder (Root : String; Capture : String := "file"; Max_Age : Natural := 0) return Routes.Folder_Route
      with SPARK_Mode => Off;

end Sparrow.Http.Static;
