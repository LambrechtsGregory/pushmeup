require 'socket'
require 'openssl'
require 'json'
require "pushmeup/apns/apnsnotification"

class APNS
  
  def initialize(pem, pass)
      @host = 'gateway.sandbox.push.apple.com'
      @port = 2195
      @pem = pem
      @pass = pass
  end
  
  def send_notification(device_token, message)
    n = ApnsNotification.new(device_token, message)
    send_notifications([n])
  end
  
  def send_notifications(notifications)
    sock, ssl = open_connection
    
    notifications.each do |n|
        ssl.write(n.packaged_notification)
      end

    ssl.close
    sock.close
  end
  
  def feedback
    sock, ssl = feedback_connection

    apns_feedback = []

    while line = ssl.read(38)   # Read lines from the socket
      line.strip!
      f = line.unpack('N1n1H140')
      apns_feedback << { :timestamp => Time.at(f[0]), :token => f[2] }
    end

    ssl.close
    sock.close

    return apns_feedback
  end
  
  protected

  def open_connection
    raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless @pem
    raise "The path to your pem file does not exist!" unless File.exist?(@pem)
    
    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(@pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(@pem), @pass)

    sock         = TCPSocket.new(@host, @port)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
    ssl.connect

    return sock, ssl
  end
  
  def feedback_connection
    raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless @pem
    raise "The path to your pem file does not exist!" unless File.exist?(@pem)
    
    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(@pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(@pem), @pass)
    
    fhost = self.host.gsub('gateway','feedback')
    
    sock         = TCPSocket.new(fhost, 2196)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock, context)
    ssl.connect

    return sock, ssl
  end
  
end
