#!/usr/bin/env ruby

require 'pg'

#puts 'Version of libpg: ' + PG.library_version.to_s
initial_db_name = 'postgres'
db_name = "hackmate"
table_name = "hm_profiles"

db_params = {
    host: 'localhost',
    port: 5432,
    dbname: initial_db_name,
    user: 'useruser',
    password: '1234'
}

table_params = "create table hm_profiles(
	profile_id SERIAL PRIMARY KEY,
  profile_name varchar(200) NOT NULL,
	target_system_name varchar(100) NOT NULL,
	ipv4 inet NOT NULL,
	ipv6 inet NULL,
  mac_address MACADDR NULL,
	port integer NULL,
	url varchar(200) NULL,
	db_type varchar(100) NULL
)"

#connection = PG.connect(dbname: 'postgres', user: 'useruser', password: '1234') #Initialize
def create_role()
  connection = PG.connect(host: 'localhost', port: 5432, dbname: 'your_database_name', user: 'your_username', password: 'your_password')

  # Check if the user exists
  user_exists = connection.exec_params("SELECT EXISTS (SELECT FROM pg_user WHERE usename = $1)", ['useruser']).getvalue(0, 0)

  unless user_exists == 't'
    # Create the user with superuser role and password
    connection.exec_params("CREATE USER useruser WITH SUPERUSER PASSWORD '1234'")
    puts "User 'useruser' created successfully."
  else
    puts "User 'useruser' already exists."
  end

rescue PG::Error => e
  puts "Error occurred: #{e.message}"

ensure
  connection.close if connection

end

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
create_table(db_name, db_params, table_name, table_params)
