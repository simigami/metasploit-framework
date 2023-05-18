def create_file(dir, auth)
    timestamp = Time.now.strftime('%Y-%m-%d_%H-%M-%S')
    file_name = "nmap_#{timestamp}.txt"
    file_path = File.join(dir, file_name)
  
    # Open the file in write mode and write content to it
    File.new(file_path, 'w')
    File.chmod(auth, file_path)
    file_name
end

# Example usage
# directory = "/home/user/Desktop/Capstone/HackMate/nmap_logs"
# create_file(directory)