# hm.rb

# Define the command logic
def cmd_hm(*args)
  print_status("Hello World")
end

# Register the command with the framework
def self.commands
  {
    "hm" => "Execute custom command hm",
  }
end

# Register the command to Metasploit
register_console_command("hm", "Execute custom command hm") { |*args| cmd_hm(*args) }
