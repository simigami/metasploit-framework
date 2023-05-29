# -*- coding: binary -*-
require 'msf'
require 'pg'
require 'csv'
require 'open3'
require 'fileutils'

module Msf
  module Test
    def create_role(access_params, username, userauth, userpasswd)
      begin
        connection = PG.connect(host: "#{access_params[:host]}", port: "#{access_params[:port]}", dbname: "#{access_params[:dbname]}", user: "#{access_params[:user]}", password: "#{access_params[:password]}")

        connection.exec_params("CREATE USER #{username} WITH #{userauth} PASSWORD '#{userpasswd}'")
      rescue PG::Error => e
        puts "Error occurred: #{e.message}"

      ensure
        connection.close if connection
      end

    end

    def create_database(access_params, dbname)
      begin
        puts access_params
        
        connection = PG.connect(host: "#{access_params[:host]}", port: "#{access_params[:port]}", dbname: "#{access_params[:dbname]}", user: "#{access_params[:user]}", password: "#{access_params[:password]}")
        
        
        connection.exec("CREATE DATABASE #{dbname}")

        access_params[:dbname] = dbname

        connection = PG::Connection.new(access_params)

      rescue PG::Error => e
        puts "Error occurred: #{e.message}"

      ensure
        connection.close if connection
      end
    end

    def connect_to_database(db_params)
      connection = PG::Connection.new(db_params)
    end

    def create_table(access_params, table_params)
      begin
        connection = PG::Connection.new(access_params)
        connection.exec(table_params)

      rescue PG::Error => e
        puts "Error: #{e.message}"
      ensure
        connection.close if connection
      end
    end

    def insert_data_into_profile_table(access_params, field_params)
      begin
        select_query = "SELECT COUNT(*) FROM hm_profiles WHERE profile_name = $1"
        insert_query = "INSERT INTO hm_profiles (profile_name, target_system_name, ipv4, ipv6, mac_address, port, url, db_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        delete_query = "DELETE FROM hm_profiles WHERE profile_name = $1"
        update_query = "UPDATE hm_profiles SET ipv4 = $1, ipv6 = $2, mac_address = $3, port = $4, url = $5, db_type = $6 WHERE profile_name = $7"

        connection = PG::Connection.new(access_params)

        #Check if profile_taget is already exists
        result = connection.exec_params(select_query, [field_params[:profile_name]])

        record_count = result.getvalue(0, 0).to_i

        #If Recode is more then 2, erase all and insert
        if record_count >= 2
          # Delete all existing records with matching profile_name and target_system_name
          delete_query = "DELETE FROM hm_profiles WHERE profile_name = $1"
          connection.exec_params(delete_query, [field_params[:profile_name]])

          puts "Deleted #{record_count} existing records. And Make New One"

          connection.exec_params(
            insert_query,
            [
              field_params[:profile_name],
              field_params[:target_system_name],
              field_params[:ipv4],
              field_params[:ipv6],
              field_params[:mac_address],
              field_params[:port],
              field_params[:url],
              field_params[:db_type]
            ]
          )
        end
        #If Recode is 1, then Update data
        if record_count == 1
          # Update the existing record with new information
          connection.exec_params(
            update_query,
            [
              field_params[:ipv4],
              field_params[:ipv6],
              field_params[:mac_address],
              field_params[:port],
              field_params[:url],
              field_params[:db_type],
              field_params[:profile_name],
              field_params[:target_system_name]
            ]
          )

          puts "Data updated successfully."
        end

        if record_count == 0
        #If Recode is 0, then Insert data
          connection.exec_params(
            insert_query,
            [
              field_params[:profile_name],
              field_params[:target_system_name],
              field_params[:ipv4],
              field_params[:ipv6],
              field_params[:mac_address],
              field_params[:port],
              field_params[:url],
              field_params[:db_type]
            ]
          )
        end

      rescue PG::Error => e
        puts "Error: #{e.message}"
      ensure
        connection.close if connection
      end
    end

    def insert_data_into_nmap_table(access_params, field_params, insert_query)
      begin
        connection = PG::Connection.new(access_params)

        select_query = "SELECT COUNT(*) FROM hm_nmap_result WHERE profile_name = $1"
        result = connection.exec_params(select_query, [field_params[:profile_name]])

        record_count = result.getvalue(0, 0).to_i

        #If Recode is more then 2, erase all and insert
        if record_count >= 1
          # Delete all existing records with matching profile_name and target_system_name
          delete_query = "DELETE FROM hm_nmap_result WHERE profile_name = $1"
          connection.exec_params(delete_query, [field_params[:profile_name]])

        end

        connection.exec_params(
          insert_query,
          [
            field_params[:profile_name],
            field_params[:ipv4],
            field_params[:ipv6],
            field_params[:mac_address],
            "{#{field_params[:port].join(',')}}",
            "{#{field_params[:port_description].map { |desc| "'#{desc}'" }.join(',')}}",
            "{#{field_params[:version_names].map { |name| "'#{name}'" }.join(',')}}",
            field_params[:OS_Guessing]
          ]
        )

      rescue PG::Error => e
        puts "Error: #{e.message}"
      ensure
        connection.close if connection
      end
    end

    def import_data_into_va_result_table(access_params, profile_name, target_name, csv_location)
      begin

        connection = PG::Connection.new(access_params)

        rows = CSV.read(csv_location)

        if rows[0][0] == 'IP'
          delete_first_row(csv_location)
        end

        rows = CSV.read(csv_location)

        if rows[0][0] != "#{profile_name}"
          unshift_CSV(csv_location, rows, profile_name, target_name)
        end

        delete_query = "DELETE FROM hm_va_result WHERE profile_name = $1"
        connection.exec_params(delete_query, [profile_name])

        CSV.foreach(csv_location) do |row|
          profile_name = row[0]
          target_system_name = row[1]
          ip = row[2]
          port = row[3].to_i
          port_protocol = row[4]
          cvss = row[5]
          nvt_name = row[6]
          summary = row[7]
          specific_result = row[8]
          cves = row[9]
          vulnerability_insight = row[10]

          insert_query = "INSERT INTO public.hm_va_result (profile_name, target_system_name, ip, port, port_protocol, cvss, nvt_name, summary, specific_result, cves, vulnerability_insight)
                          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"

          connection.exec_params(insert_query, [profile_name, target_system_name, ip, port, port_protocol, cvss, nvt_name, summary, specific_result, cves, vulnerability_insight])
        end
      rescue PG::Error => e
        puts "Error: #{e.message}"
      ensure
        connection.close if connection
      end
    end


    def create_folder(dir, foldername, auth)
      begin
        folder_path = File.join(dir, foldername)

        Dir.mkdir(folder_path, auth)

        return folder_path

      rescue Errno::EEXIST
        puts "Folder already exists."
        return folder_path

      rescue Errno::EACCES
        puts "Permission denied to create folder. Are you root?"
        return folder_path
      end
    end

    def create_file(dir, first_name, extension_name, auth)
      timestamp = Time.now.strftime('%Y-%m-%d_%H-%M-%S')
      file_name = "#{first_name}_#{timestamp}.#{extension_name}"
      file_path = File.join(dir, file_name)

      # Open the file in write mode and write content to it
      File.new(file_path, 'w')
      File.chmod(0666, file_path)

      return file_name
    end

    def execute_command(user_input)
      begin
        require 'open3'
        tokens = user_input.split(" ")
        command = tokens[0]
        arguments = tokens[1..-1]
        Open3.popen3(command, *arguments) do |stdin, stdout, stderr, wait_thr|
            output = stdout.read.chomp
            errors = stderr.read.chomp
            unless wait_thr.value.success?
                puts "Error: #{errors}"
            end
            puts output
        end
      rescue LoadError
          puts 'The open3 module is not available. Installing...'
          system('gem install open3')
          Gem.clear_paths
          require 'open3'
      end
    end

    def import_va_result_csv_to_DB(access_params, csv_location)
      begin
        connection = PG::Connection.new(access_params)

        CSV.foreach(csv_location) do |row|
          profile_name = row[0]
          target_system_name = row[1]
          ip = row[2]
          port = row[3]
          port_protocol = row[4]
          cvss = row[5]
          nvt_name = row[6]
          summary = row[7]
          specific_result = row[8]
          cves = row[9]
          vulnerability_insight = row[10]

          insert_query = "INSERT INTO public.hm_va_result (profile_name, target_system_name, ip, port, port_protocol, cvss, nvt_name, summary, specific_result, cves, vulnerability_insight)
                          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
          connection.exec_params(insert_query, [profile_name, target_system_name, ip, port, port_protocol, cvss, nvt_name, summary, specific_result, cves, vulnerability_insight])
        end
      rescue PG::Error => e
        puts "Error: #{e.message}"
      ensure
        connection.close if connection
      end
    end

    def delete_first_row(csv_location)
      rows = CSV.read(csv_location)

      modified_rows = rows[1..-1] # Remove the first column from each row

      #puts modified_rows
      CSV.open(csv_location, 'w') { |csv| modified_rows.each { |row| csv << row } }
    end

    def unshift_CSV(csv_location, modified_rows, profile, target)
      rows = CSV.read(csv_location)

      modified_rows = rows.map.with_index do |row, index|
        [profile, target] + row
      end

      CSV.open(csv_location, 'w') do |csv|
        modified_rows.each do |row|
          csv << row
        end
      end
    end

  end
end

#!/usr/bin/env ruby
