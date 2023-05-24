require 'msf/core'
require 'msf/base'
require 'open3'
require 'csv'
require 'pathname'

module Msf
  class Plugin::HM < Msf::Plugin
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher
      include Msf::Modules

      def name
        "HackMate"
      end

      def desc
        'HackMate Test'
      end

      def commands
      {
            'HM' => 'Auto Attack Example',
      }
      end

      #
      # This method handles the sample command.
      #
      def cmd_HM()
        profile_name = "Profile1"
        target_system_name = "Target1"
        row_name = "summary"

        temp = find_good_vuln_from_summary(profile_name, target_system_name, row_name)
        find_vuln(temp)
        add_keyword_and_search_exploit_vuln(profile_name, target_system_name)
        # self.driver.run_single("search java_rmi")
        # self.driver.run_single("use exploit/multi/misc/java_rmi_server")
      end

      def search_vuln_from_db(profile_name, target_system_name, row_name)
        summaries = []
        db_params = {
          host: 'localhost',
          port: 5432,
          dbname: 'hackmate',
          user: 'useruser',
          password: '1234'
        }

        connection = PG.connect(db_params)

        query = "SELECT #{row_name} FROM hm_va_result WHERE profile_name = '#{profile_name}' AND target_system_name = '#{target_system_name}'"

        result = connection.exec(query)

        result.each do |row|
          summary = row["#{row_name}"]
          summaries << summary
        end

        return summaries
      end

      def find_good_vuln_from_summary(profile_name, target_system_name, row_name)
        good_vuln = ["httponly", "backdoor", "ruby", "exec", "rexec", "XSS", "remote", "EOL", "rlogin", "RCE", "DistCC", "AJP", "VNC", "postgres", "UnrealIRCd", "MySQL", "rsh", "PHP", "PUT", "DELETE", "java_RMI", "vsftpd", "FTP", "phpinfo", "OpenSSL", "TWiki", "CSRF", "STARTTLS", "jQuery", "Samba", "SMB", "SSRF", "SSLv", "TRACK", "SSH", "SSL", "TLS", "doc", "LFI", "SMTP", "VRFY", "EXPN", "ICMP"]
        good_array = []
        vuln_num = 1

        summaries = search_vuln_from_db(profile_name, target_system_name, row_name)
        summaries.each do |row|
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

      def find_vuln(good_array)
        data_array = []
        commands = {
          search: 'search',
          exploit: 'exploit',
          use: 'use',
          show: 'show'
        }
        default_path = "/home/user/Desktop/Everything_Related_To_Git/Projects/Metasploit_Fork/metasploit-framework"
        result_csv_folder = "/home/user/Desktop/Everything_Related_To_Git/Projects/Metasploit_Fork/hackmate/CSV_Files/Search_Result/"
        vuln_number = 1

        good_array.each do |row|
          timestamp = Time.now.strftime("%Y%m%d%H%M%S")
          csv_name = "Vuln#{vuln_number}_#{timestamp}_"

          row.each do |elem|
            result_csv_file = result_csv_folder + csv_name + elem + ".csv"
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

      def add_keyword_and_search_exploit_vuln(profile_name, target_system_name)
        folder_path = "/home/user/Desktop/Everything_Related_To_Git/Projects/Metasploit_Fork/hackmate/CSV_Files/Search_Result/"
        output_csv_path = "/home/user/Desktop/Everything_Related_To_Git/Projects/Metasploit_Fork/hackmate/CSV_Files/Final_Results/"
        output_rows = []
        flag = 1

        timestamp = Time.now.strftime("%Y%m%d%H%M%S")
        output_csv_name = "#{profile_name}_#{target_system_name}_result_#{timestamp}"
        output_csv = output_csv_path + output_csv_name + ".csv"

        Dir.glob(File.join(folder_path, '*')).each do |file_path|
          CSV.foreach(file_path) do |row|
            next if output_rows.any? { |existing_row| existing_row[1..-1] == row[1..-1] }
            output_rows << row if flag
            output_rows << row if (row[1] && row[1].include?('exploit')) && (row[3] && (row[3].include?('great') || row[3].include?('excellent')))
            flag=0
          end
        end

        output_rows.uniq!
        output_rows.sort_by! {|row| row[1]}

        CSV.open(output_csv, 'w') do |csv|
          output_rows.each do |row|
            csv << row
          end
        end

        Dir.glob(File.join(folder_path, '*.csv')).each do |file_path|
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
