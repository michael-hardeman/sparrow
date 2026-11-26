--  DEFLATE compression (RFC 1951), the format inside gzip and HTTP's Content-Encoding: gzip. LZ77 over a
--  32 KiB window, with hash chains and one step of lazy matching, then each block written as whichever of
--  dynamic Huffman, fixed Huffman or stored is smallest. Compression only: Sparrow never inflates.
--
--  SPARK: no run-time errors, and nothing is written outside Output.
with Interfaces; use Interfaces;

package Sparrow.Deflate with SPARK_Mode is

   --  The working memory of one compression, about 200 KiB. Allocate one per task and reuse it: Compress
   --  resets what it needs.
   type State is limited private;

   --  Input compressed into Output (Output'First .. Last). Fits is False, and Output's content unusable, when
   --  the compressed form does not fit: give Output only the room a result is worth having in, and an input
   --  that does not shrink stops costing time once it has filled it.
   procedure Compress
     (Work   : in out State;
      Input  : String;
      Output : in out String;
      Last   : out Natural;
      Fits   : out Boolean)
      with Pre  => Input'First >= 1 and then Input'Last < Positive'Last - 512 and then Input'Last >= Input'First - 1
                   and then Output'First >= 1
                   and then Output'Last < Positive'Last and then Output'Last >= Output'First - 1,
           Post => Last in Output'First - 1 .. Output'Last;

private

   Window_Size   : constant := 32_768;
   Hash_Bits     : constant := 15;
   Block_Symbols : constant := 16_384;   --  literals and matches per block

   type Hash_Index is mod 2 ** Hash_Bits;
   type Window_Index is mod Window_Size;

   --  Provers model Interfaces modular types as bit vectors, which hides their relation to string indexes.
   type Chain_Offset is new Unsigned_32 with Annotate => (GNATprove, No_Bitwise_Operations);

   --  Head: for each hash of three bytes, the offset (from 1) of the latest position with it, or 0.
   --  Chain: for each position's offset modulo the window, how far back the previous one with its hash is, or 0.
   type Head_Table is array (Hash_Index) of Chain_Offset;
   type Chain_Table is array (Window_Index) of Unsigned_16;

   subtype Symbol_Index is Positive range 1 .. Block_Symbols;
   type Symbol_Table is array (Symbol_Index) of Unsigned_16;

   type State is limited record
      Head    : Head_Table   := [others => 0];
      Chain   : Chain_Table  := [others => 0];
      Lengths : Symbol_Table := [others => 0];   --  the block's symbols: 0 for a literal, else a match's length
      Values  : Symbol_Table := [others => 0];   --  the literal's byte, or the match's distance
   end record;

end Sparrow.Deflate;
