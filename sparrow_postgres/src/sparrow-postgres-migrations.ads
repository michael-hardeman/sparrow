--  Applies Sparrow.Migrations steps to a Postgres database, recording each version in a schema_migrations
--  table.
--
--     Migrations.Apply (Db, Steps);   --  at start-up, before Prepare (the statements may need the new schema)
--
--  Apply runs every pending step in one transaction holding an advisory lock, so servers starting together
--  apply each step once and a failing step leaves the database as it was (Postgres DDL is transactional).
--  A step's SQL may hold several statements but not its own BEGIN or COMMIT, nor CREATE INDEX CONCURRENTLY.
--  A database already past the last step (a newer program has run) is left alone.
with Sparrow.Migrations;

package Sparrow.Postgres.Migrations with SPARK_Mode => Off is

   Migration_Error : exception;

   subtype Migration_Step is Sparrow.Migrations.Migration_Step;
   subtype Step_List is Sparrow.Migrations.Step_List;

   No_Steps : Step_List renames Sparrow.Migrations.No_Steps;

   function Step (Version : Positive; Sql : String) return Migration_Step renames Sparrow.Migrations.Step;

   --  Bring This up to the last step. Raises Program_Error when versions do not increase, Migration_Error
   --  naming the step when one fails (nothing of the run is then kept), and Connection_Error when the
   --  connection does.
   procedure Apply (This : in out Connection; Steps : Step_List)
     with Global            => (In_Out => Sparrow.Postgres.Server),
          Exceptional_Cases => (Program_Error => True, Migration_Error => True, Connection_Error => True),
          Post              => Is_Connected (This);

   --  The last version applied; 0 for a database never migrated.
   function Version (This : in out Connection) return Natural
     with Global => (In_Out => Sparrow.Postgres.Server),
          Post   => Is_Connected (This);

end Sparrow.Postgres.Migrations;
