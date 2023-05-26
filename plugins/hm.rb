require 'msf/core'
require 'msf/base'
require 'open3'
require 'csv'
require 'pathname'

module Msf
  class Plugin::HM < Msf::Plugin
    class ConsoleCommandDispatcher
      include Msf::Test
      include Msf::Ui::Console::CommandDispatcher
      include Msf::Modules

      @@access_params = {
        host: 'localhost',
        port: 5432,
        dbname: 'postgres',
        user: 'useruser',
        password: '1234'
      }

      def name
        "HackMate"
      end

      def desc
        'HackMate Test'
      end

      def commands
      {
            'HM' => 'Auto Attack Example',
            'HM_Init' => 'Initialize HackMate',
            'HM_Nmap' => 'Nmap Scan',
            'HM_Vuln' => 'Get Exploit Path from VA Result'
      }
      end

      #
      # This method handles the sample command.
      #
      def cmd_HM()
        profile_name = "Profile1"
        target_system_name = "Target1"
        row_name = "summary"

        # temp = find_good_vuln_from_summary(profile_name, target_system_name, row_name)

        # find_vuln(temp)
        # add_keyword_and_search_exploit_vuln(profile_name, target_system_name)
        # self.driver.run_single("search java_rmi")
        # self.driver.run_single("use exploit/multi/misc/java_rmi_server")
      end

      def cmd_HM_Init()
        profile_table_params = "create table hm_profiles(
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
        nmap_table_params = "create table hm_nmap_result (
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
        va_result_table_params = "create table hm_va_result(
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
        profile_field_params = {
            profile_name: 'Profile1',
            target_system_name: 'Test2',
            ipv4: '192.168.0.123',
            ipv6: nil,
            mac_address: nil,
            port: 8000,
            url: 'http://www.example.com2',
            db_type: 'postgresql'
        }

        dbname = "hackmate"
        profile_insert_query = "INSERT INTO hm_profiles (profile_name, target_system_name, ipv4, ipv6, mac_address, port, url, db_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"

        #create_role(access_params, username, userauth, userpasswd)
        @@access_params[:user] = "useruser"
        @@access_params[:password] = "1234"

        create_database(@@access_params, dbname)
        create_table(@@access_params, profile_table_params)
        create_table(@@access_params, nmap_table_params)
        create_table(@@access_params, va_result_table_params)
        insert_data_into_profile_table(@@access_params, profile_field_params, profile_insert_query)

        base_dir = Dir.pwd()
        folder_name = "HackMate"
        create_folder(base_dir, folder_name, 0777)

        hackmate_dir = base_dir + "/#{folder_name}"
        folder_name = "Nmap_Result"
        create_folder(hackmate_dir, folder_name, 0777)

        @@nmap_dir = hackmate_dir + "/#{folder_name}"
        create_csv_folder_and_put_file(hackmate_dir)

        csv_dir = hackmate_dir + "/CSV"
        @@va_result_dir = create_folder_inside_csv_folder(csv_dir, "VA_Result")
        @@exploit_search_dir = create_folder_inside_csv_folder(csv_dir, "Exploit_Search_Result")
        @@final_result_dir = create_folder_inside_csv_folder(csv_dir, "Final_Result")
      end

      def cmd_HM_Nmap()
        #create_file(hackmate_dir, file_name, extension_name, 0666)
        profile_name = "Profile1"
        target_system_name = "TS1"
        nmap_command_params = {
          cmd: "nmap",
          taget_profile_name: "#{profile_name}_#{target_system_name}",
          target: "192.168.0.117", #Target System IP Addr
          nmap_options: "-F -T4 -O -oN",
          auth: 0666
        }
        table_name = "hm_nmap_result"
        run_nmap(@@nmap_dir, nmap_command_params, @@access_params, table_name)
      end

      def cmd_HM_Vuln()
        profile_name = "Profile1"
        target_system_name = "Target1"
        row_name = "summary"
        import_data_into_va_result_table(@@access_params, @@va_result_dir+"/report.csv")
        good_vuln = find_good_vuln_from_summary(@@access_params, profile_name, target_system_name, row_name)

        find_vuln(@@exploit_search_dir+"/", good_vuln)
        add_keyword_and_search_exploit_vuln(profile_name, target_system_name, @@exploit_search_dir, @@final_result_dir)
      end

      def run_nmap(nmap_dir, nmap_command_params, access_params, table_name)
        begin
          file_name = create_file(nmap_dir, "#{nmap_command_params[:taget_profile_name]}_Nmap_Result", "txt", 0666)

          log_file_path = nmap_dir + "/#{file_name}"

          command = "#{nmap_command_params[:cmd]} #{nmap_command_params[:nmap_options]} #{log_file_path} #{nmap_command_params[:target]}"

          self.driver.run_single("#{command}")

          log = File.read(log_file_path)

          ip_address = log[/Nmap scan report for (\S+)/, 1]
          if(ip_address == 'localhost')
            ip_address = '127.0.0.1'
          end
          mac_address = log[/MAC Address: (\S+)/, 1]
          ports = log.scan(/^\s*(\d+)\/\w+\s+/).flatten
          service_names = log.scan(/^\s*\d+\/\w+\s+\w+\s+(\S+)/).flatten
          version_names = log.scan(/\d+\/\w+\s+\w+\s+\w+\s+((?:\S+ )*\S*)$/).flatten.map { |str| str.empty? ? "NULL" : "'#{str}'" }
          result = {
            profile_name: nmap_command_params[:taget_profile_name],
            ports: ports,
            service_names: service_names,
            version_names: version_names,
            ip_address: ip_address,
            mac_address: mac_address
          }

          puts result[:ip_address]

          field_params = {
            profile_name: result[:profile_name],
            ipv4: result[:ip_address],
            ipv6: nil,
            mac_address: result[:mac_address],
            port: result[:ports],
            port_description: result[:service_names],
            version_names: result[:version_names],
            OS_Guessing: nil
          }

          insert_query = "INSERT INTO #{table_name} (profile_name, ipv4, ipv6, mac_address, port, port_description, version_names, OS_Guessing) VALUES ($1, $2, $3, $4, $5::integer[], $6::varchar[], $7::varchar[], $8)"

          insert_data_into_nmap_table(access_params, field_params, insert_query)

        rescue PG::Error => e
          puts "Error: #{e.message}"
        ensure
        end
      end

      def create_csv_folder_and_put_file(dir)
        foldername = "CSV"
        csv_dir = create_folder(dir, foldername, 0666)

        #put file code
      end

      def create_folder_inside_csv_folder(dir, foldername)
        folder_inside_csv_dir = create_folder(dir, foldername, 0666)

        return folder_inside_csv_dir
      end

      def search_vuln_from_db(access_params, profile_name, target_system_name, row_name)
        summaries = []
        connection = PG.connect(access_params)

        query = "SELECT #{row_name} FROM hm_va_result WHERE profile_name = '#{profile_name}' AND target_system_name = '#{target_system_name}'"


        result = connection.exec(query)

        result.each do |row|
          #puts row
          summary = row["#{row_name}"]
          # puts summary
          summaries << summary
        end

        return summaries
      end

      def find_good_vuln_from_summary(access_params, profile_name, target_system_name, row_name)
        good_vuln = ["httponly", "backdoor", "ruby", "exec", "rexec", "XSS", "remote", "EOL", "rlogin", "RCE", "DistCC", "AJP", "VNC", "postgres", "UnrealIRCd", "MySQL", "rsh", "PHP", "PUT", "DELETE", "java_RMI", "vsftpd", "FTP", "phpinfo", "OpenSSL", "TWiki", "CSRF", "STARTTLS", "jQuery", "Samba", "SMB", "SSRF", "SSLv", "TRACK", "SSH", "SSL", "TLS", "doc", "LFI", "SMTP", "VRFY", "EXPN", "ICMP"]
        good_array = []
        vuln_num = 1

        summaries = search_vuln_from_db(access_params, profile_name, target_system_name, row_name)
        summaries.each do |row|
          #puts row
          temp = []
          good_vuln.each do |keyword|
            if row.include?(keyword)
              temp << keyword
            end
          end
          good_array << temp
        end
        # good_array.each do |row|
        #   row.each do |elem|
        #     puts elem
        #   end
        # end

        return good_array
      end

      def find_vuln(result_folder, good_array)
        data_array = []
        commands = {
          search: 'search',
          exploit: 'exploit',
          use: 'use',
          show: 'show'
        }
        vuln_number = 1

        good_array.each do |row|
          timestamp = Time.now.strftime("%Y%m%d%H%M%S")
          csv_name = "Vuln#{vuln_number}_#{timestamp}_"

          row.each do |elem|
            result_csv_file = result_folder + csv_name + elem + ".csv"
            self.driver.run_single("#{commands[:search]} #{elem} -o #{result_csv_file}")
          end
          vuln_number += 1
        end
      end
        # search_params = Msf::Modules::Metadata::Search.parse_search_string('java_rmi')
        # result = Msf::Modules::Metadata::Cache.instance.find(search_params)
        # result.each do |module_data|
        #   module_name = module_data.name
        #   module_description = module_data.description
        #   date = module_data.disclosure_date
        #   ref = module_data.path.sub(/^#{Regexp.escape(default_path)}/, '')

        #   data_array << {
        #     "Module Name" => module_name,
        #     "Module Description" => module_description,
        #     "Module Date" => date,
        #     "Ref" => ref
        #   }
        # end
        # return data_array
      # end

      def add_keyword_and_search_exploit_vuln(profile_name, target_system_name, search_result_folder_dir, findal_result_dir)
        output_rows = []
        flag = 1

        timestamp = Time.now.strftime("%Y%m%d%H%M%S")
        output_csv_name = "#{profile_name}_#{target_system_name}_result_#{timestamp}"


        output_csv_path = findal_result_dir + "/" + output_csv_name + ".csv"

        Dir.glob(File.join(search_result_folder_dir, '*')).each do |file_path|
          CSV.foreach(file_path) do |row|
            next if output_rows.any? { |existing_row| existing_row[1..-1] == row[1..-1] }
            output_rows << row if flag==1
            output_rows << row if (row[1] && row[1].include?('exploit')) && (row[3] && (row[3].include?('great') || row[3].include?('excellent')))
            flag=0
          end
        end

        output_rows.uniq!
        output_rows.sort_by! {|row| row[1]}

        CSV.open(output_csv_path, 'w') do |csv|
          output_rows.each do |row|
            csv << row
          end
        end
        File.chmod(0777, output_csv_path)

        Dir.glob(File.join(search_result_folder_dir, '*.csv')).each do |file_path|
          FileUtils.rm(file_path)
        end
      end
    end
    #
    # The constructor is called when an instance of the plugin is created.  The
    # framework instance that the plugin is being associated with is passed in
    # the framework parameter.  Plugins should call the parent constructor when
    # inheriting from Msf::Plugin to ensure that the framework attribute on
    # their instance gets set.
    #
    def initialize(framework, opts)
      super

      # If this plugin is being loaded in the context of a console application
      # that uses the framework's console user interface driver, register
      # console dispatcher commands.
      add_console_dispatcher(ConsoleCommandDispatcher)
      print_status("HM plugin loaded.")

    end

    def cleanup
      remove_console_dispatcher('HackMate')
    end
  end
end
