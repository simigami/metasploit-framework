# User Created with password 536d65f4-4ff1-4031-b79b-a0e91641210e

#!/usr/bin/env ruby
require 'csv'
require 'pg'


initial_db_name = 'hackmate'

db_params = {
    host: 'localhost',
    port: 5432,
    dbname: initial_db_name,
    user: 'useruser',
    password: '1234'
}

table_name = "hm_va_result"
file_name = "/report.csv"
log_dir = "/home/user/Desktop/Everything_Related_To_Git/Projects/Metasploit_Fork/hackmate/CSV_Files/VA_Result"
log_location = log_dir + file_name
temp = {
  profile_name: "Profile1",
  target_system_name: "Target1"
}
modified_rows = []

def unshift_CSV(log_location, modified_rows, profile, target)
  CSV.foreach(log_location) do |row|
    row.unshift(profile, target)
    modified_rows << row
  end

  CSV.open(log_location, 'w') do |csv|
    modified_rows.each do |row|
      csv << row
    end
  end
end

def import_csv_to_DB(db_params, log_location)
    begin
      connection = PG::Connection.new(db_params)

      CSV.foreach(log_location) do |row|
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

#unshift_CSV(log_location, modified_rows, temp[:profile_name], temp[:target_system_name])
import_csv_to_DB(db_params, log_location)
