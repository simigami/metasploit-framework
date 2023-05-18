#!/usr/bin/env ruby

require 'pg'
require_relative 'makedb'

db_params = {
    host: 'localhost',
    port: 5432,
    dbname: 'hackmate',
    user: 'useruser',
    password: '1234'
}

data_params = {
    profile_name: 'Profile1',
    target_system_name: 'Test2',
    ipv4: '192.168.0.123',
    ipv6: nil,
    mac_address: nil,
    port: 8000,
    url: 'http://www.example.com2',
    db_type: 'postgresql'
}

insert_query = "INSERT INTO hm_profiles (profile_name, target_system_name, ipv4, ipv6, mac_address, port, url, db_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"

def insert_data_into_profile_table(db_params, data_params, insert_query)
    begin
      connection = PG::Connection.new(db_params)
  
      connection.exec_params(
        insert_query,
        [
          data_params[:profile_name],
          data_params[:target_system_name],
          data_params[:ipv4],
          data_params[:ipv6],
          data_params[:mac_address],
          data_params[:port],
          data_params[:url],
          data_params[:db_type]
        ]
      )
  
      # Data manipulation
      # update_query = "UPDATE hm_profiles SET ipv4 = $1 WHERE target_system_name = $2"
      # connection.exec_params(update_query, ['192.168.0.2', 'system1'])
  
    rescue PG::Error => e
      puts "Error: #{e.message}"
    ensure
      connection.close if connection
    end
end

def insert_data_into_nmap_table(db_params, data_params, insert_query)
    begin
      connection = PG::Connection.new(db_params)
  
      connection.exec_params(
        insert_query,
        [
          data_params[:profile_name],
          data_params[:ipv4],
          data_params[:ipv6],
          data_params[:mac_address],
          "{#{data_params[:port].join(',')}}",
          "{#{data_params[:port_description].map { |desc| "'#{desc}'" }.join(',')}}",
          "{#{data_params[:version_names].map { |name| "'#{name}'" }.join(',')}}",
          data_params[:OS_Guessing]
        ]
      )
      # Data manipulation
      # update_query = "UPDATE hm_profiles SET ipv4 = $1 WHERE target_system_name = $2"
      # connection.exec_params(update_query, ['192.168.0.2', 'system1'])
  
    rescue PG::Error => e
      puts "Error: #{e.message}"
    ensure
      connection.close if connection
    end
end

insert_data_into_profile_table(db_params, data_params, insert_query)