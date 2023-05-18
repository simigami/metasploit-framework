require 'msf/core'
require 'msf/base'
require 'open3'
require 'modules.rb'

module Msf
class Plugin::HM < Msf::Plugin
  class ConsoleCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher
    include Msf::Ui::Console::CommandDispatcher::Common::Modules

    def name
      "HackMate"
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
        command_string = "use -h".join(" ")
        cmd_use(command_string)
    end

    def find_vuln()
      default_path = "/home/user/Desktop/Everything_Related_To_Git/Projects/Metasploit_Fork/metasploit-framework"
      data_array = []

      search_params = Msf::Modules::Metadata::Search.parse_search_string('java_rmi')
      result = Msf::Modules::Metadata::Cache.instance.find(search_params)
      result.each do |module_data|
        module_name = module_data.name
        module_description = module_data.description
        date = module_data.disclosure_date
        ref = module_data.path.sub(/^#{Regexp.escape(default_path)}/, '')

        data_array << {
          "Module Name" => module_name,
          "Module Description" => module_description,
          "Module Date" => date,
          "Ref" => ref
        }
      end
      return data_array
    end

    def use_that_vuln()
      found_vuln = find_vuln() #Get Array of Search Vulnerability

      found_vuln.each do |elem|
        if elem["Ref"] == "/modules/exploits/multi/misc/java_rmi_server.rb"
          query_string = "use " + elem["Ref"]

          search_params = Msf::Modules::Metadata::Search.parse_search_string(query_string)
          result = Msf::Modules::Metadata::Cache.instance.find(search_params)
          result.each do |module_data|
            module_name = module_data.name
            puts "Module Name: #{module_name}" # Vulnerability name
            puts "------------------------"
          end

        end
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

    def name
      'HackMate'
    end

    def desc
      'HackMate Test'
    end
end
end
