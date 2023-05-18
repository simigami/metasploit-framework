require 'json'

require_relative 'makedb'
require_relative 'makeprofile'
require_relative 'makeLogFile'
require_relative 'callProcess'

#alter USER useruser
#\c hackmate

# Approx 1 min per 0.0.0.0/24 subnet -PP -sn option.
db_name = "hackmate"
db_params = {
  host: 'localhost',
  port: 5432,
  dbname: 'hackmate',
  user: 'useruser',
  password: '1234'
}

table_name = "hm_nmap_result"
table_params = "create table hm_nmap_result (
  result_id SERIAL PRIMARY KEY,
  profile_name varchar(200) NOT NULL,
  ipv4 inet NOT NULL,
  ipv6 inet NULL,
  mac_address MACADDR NULL,
  port integer ARRAY NULL,
  port_description varchar(30) ARRAY NULL,
  version_names varchar(100) ARRAY NULL,
  OS_Guessing varchar(30) NULL
)"

command_params = {
  cmd: "nmap",
  taget_profile_name: "Test_To_Metasploitable2",
  target: "192.168.0.117",
  nmap_options: "-sV -T4 -O -oN",
  log_location: "/home/user/Desktop/Everything_Related_To_Git/Projects/Metasploit_Fork/hackmate/nmap_logs",
  auth: 0666
}

def run_nmap(command_params, db_name, db_params, table_name, table_params)
  file_name = create_file(command_params[:log_location], command_params[:auth])

  log_file_path = "#{command_params[:log_location]}/#{file_name}"

  command = "#{command_params[:cmd]} #{command_params[:nmap_options]} #{log_file_path} #{command_params[:target]}"

  puts command_params

  execute_command(command)

  log = File.read(log_file_path)

  ip_address = log[/Nmap scan report for (\S+)/, 1]
  mac_address = log[/MAC Address: (\S+)/, 1]
  ports = log.scan(/^\s*(\d+)\/\w+\s+/).flatten
  service_names = log.scan(/^\s*\d+\/\w+\s+\w+\s+(\S+)/).flatten
  version_names = log.scan(/\d+\/\w+\s+\w+\s+\w+\s+((?:\S+ )*\S*)$/).flatten.map { |str| str.empty? ? "NULL" : "'#{str}'" }

  #puts version_names

  result = {
    profile_name: command_params[:taget_profile_name],
    ports: ports,
    service_names: service_names,
    version_names: version_names,
    ip_address: ip_address,
    mac_address: mac_address
  }

  data_params = {
    profile_name: result[:profile_name],
    ipv4: result[:ip_address],
    ipv6: nil,
    mac_address: result[:mac_address],
    port: result[:ports],
    port_description: result[:service_names],
    version_names: result[:version_names],
    OS_Guessing: nil
  }

  create_table(db_name, db_params, table_name, table_params)

  insert_query = "INSERT INTO #{table_name} (profile_name, ipv4, ipv6, mac_address, port, port_description, version_names, OS_Guessing) VALUES ($1, $2, $3, $4, $5::integer[], $6::varchar[], $7::varchar[], $8)"

  insert_data_into_nmap_table(db_params, data_params, insert_query)
end

run_nmap(command_params, db_name, db_params, table_name, table_params)
