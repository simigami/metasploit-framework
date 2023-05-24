#!/usr/bin/env ruby

require 'pg'
require_relative 'makedb'

#puts 'Version of libpg: ' + PG.library_version.to_s
initial_db_name = 'postgres'
db_name = "hackmate"

db_params = {
    host: 'localhost',
    port: 5432,
    dbname: initial_db_name,
    user: 'useruser',
    password: '1234'
}
# table_params = "create table hm_va_result(
#   IP inet NULL,
#   Hostname text NULL,
#   Port integer NULL,
#   Port_Protocol text NULL,
#   CVSS numeric(3, 1) NULL,
#   Severity text NULL,
#   Solution_Type text NULL,
#   NVT_Name text NULL,
#   Summary text NULL,
#   Specific_Result text NULL,
#   NVT_OID text NULL,
#   CVEs text NULL,
#   Task_ID text NULL,
#   Task_Name text NULL,
#   Timestamp timestamp NULL,
#   Result_ID text NULL,
#   Impact text NULL,
#   Solution text NULL,
#   Affected_Software_OS text NULL,
#   Vulnerability_Insight text NULL,
#   Vulnerability_Detection_Method text NULL,
#   Product_Detection_Result text NULL,
#   BIDs text NULL,
#   CERTs text NULL
# )"
table_params = "create table hm_va_result(
  profile_id SERIAL PRIMARY KEY,
  profile_name varchar(200) NOT NULL,
	target_system_name varchar(100) NOT NULL,
  IP inet NULL,
  Port integer NULL,
  Port_Protocol text NULL,
  CVSS numeric(3, 1) NULL,
  NVT_Name text NULL,
  Summary text NULL,
  Specific_Result text NULL,
  CVEs text NULL,
  Vulnerability_Insight text NULL
)"

def create_table(db_name, db_params, table_name, table_params)
    begin
      connection = PG::Connection.new(db_params)

      result = connection.exec("SELECT 1 FROM pg_database WHERE datname='#{db_name}'")

      if result.ntuples == 0
        puts 'No DB, Creating DB'
        connection.exec("CREATE DATABASE #{db_name}")
        puts 'DB Create Complete'
        # Create Tables, Columns
      else
        puts 'DB Exists'
        connection.close

        db_params[:dbname] = db_name
        connection = PG::Connection.new(db_params)
        puts 'Switched to "hackmate" database.'

      end

      result = connection.exec("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '#{table_name}')")

      if result.getvalue(0, 0) == 'f'
        puts 'No Table, Creating Table'
        connection.exec(table_params)
      else
        puts 'Table Exists'
        # result = connection.exec("SELECT column_name FROM information_schema.columns WHERE table_name='hm_profiles'")
        # result.each do |row|
        #   puts row['column_name']
        # end
      end

    rescue PG::Error => e
      puts "Error: #{e.message}"
    ensure
      connection.close if connection
    end
end

table_name = "hm_va_result"
create_table(db_name, db_params, table_name, table_params)
