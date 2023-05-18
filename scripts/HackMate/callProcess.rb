begin
    require 'open3'
rescue LoadError
    puts 'The open3 module is not available. Installing...'
    system('gem install open3')
    Gem.clear_paths
    require 'open3'
end

def execute_command(user_input)
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
end