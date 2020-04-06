# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/timestamp"
require "stud/interval"
require "socket" # for Socket.gethostname

# Read mails from IMAP server
#
# Periodically scan an IMAP folder (`INBOX` by default) and move any read messages
# to the trash.
class LogStash::Inputs::IMAP < LogStash::Inputs::Base
  config_name "imap"

  default :codec, "plain"

  config :host, :validate => :string, :required => true
  config :port, :validate => :number

  config :user, :validate => :string, :required => true
  config :password, :validate => :password, :required => true
  config :secure, :validate => :boolean, :default => true
  config :verify_cert, :validate => :boolean, :default => true

  config :folder, :validate => :string, :default => 'INBOX'
  config :fetch_count, :validate => :number, :default => 50
  config :lowercase_headers, :validate => :boolean, :default => true
  config :check_interval, :validate => :number, :default => 300
  config :delete, :validate => :boolean, :default => false
  config :expunge, :validate => :boolean, :default => false
  config :mark_read, :validate => :boolean, :default => true

  # Whether to use IMAP uid to track last processed message
  config :uid_tracking, :validate => :boolean, :default => false
  config :uid_tracking_init_search, :validate => :string, :default => "ALL"

  # Path to file with last run time metadata
  config :sincedb_path, :validate => :string, :required => false

  # Determines whether to pass along the entire body for each part
  config :include_entire_body, :validate => :boolean, :required => false, :default => true

  def get_uid_last_value
    if File.exist?(@sincedb_path)
      return File.read(@sincedb_path).to_i
    else
      return nil
    end
  end

  def register
    require "net/imap" # in stdlib
    require "mail" # gem 'mail'

    if @secure and not @verify_cert
      @logger.warn("Running IMAP without verifying the certificate may grant attackers unauthorized access to your mailbox or data")
    end

    if @port.nil?
      if @secure
        @port = 993
      else
        @port = 143
      end
    end

    # Load last processed IMAP uid from file if exists
    if @sincedb_path.nil?
      datapath = File.join(LogStash::SETTINGS.get_value("path.data"), "plugins", "inputs", "imap")
      # Ensure that the filepath exists before writing, since it's deeply nested.
      FileUtils::mkdir_p datapath
      @sincedb_path = File.join(datapath, ".sincedb_" + Digest::MD5.hexdigest("#{@user}_#{@host}_#{@port}_#{@folder}"))
    end
    if File.directory?(@sincedb_path)
      raise ArgumentError.new("The \"sincedb_path\" argument must point to a file, received a directory: \"#{@sincedb_path}\"")
    end
    @logger.info("Using \"sincedb_path\": \"#{@sincedb_path}\"")

    @uid_last_value = get_uid_last_value
    @logger.info("Loading \"uid_last_value\": \"#{@uid_last_value}\"")

  end # def register

  def connect
    sslopt = @secure
    if @secure and not @verify_cert
        sslopt = { :verify_mode => OpenSSL::SSL::VERIFY_NONE }
    end
    imap = Net::IMAP.new(@host, :port => @port, :ssl => sslopt)
    imap.login(@user, @password.value)
    return imap
  end

  def run(queue)
    @run_thread = Thread.current
    Stud.interval(@check_interval, opts={:sleep_then_run => true}) do
      check_mail(queue)
    end
  end

  def check_mail(queue)
    # TODO: Maybe breakup this method in a way where the imap open
    # connection is minimized in order to support more concurrent imap
    # processing
    # TODO(sissel): handle exceptions happening during runtime:
    # EOFError, OpenSSL::SSL::SSLError
    
    @logger.debug? && @logger.debug("#{@user}@#{@host}:#{@port}/#{@folder}: Checking mail")

    imap = connect
    imap.select(@folder)

    if @uid_tracking
      if @uid_last_value
        # If there are no new messages, uid_search returns @uid_last_value
        # because it is the last message, so we need to delete it.
        ids = imap.uid_search(["UID", (@uid_last_value+1..-1)]).delete_if { |uid|
          uid <= @uid_last_value
        }
      else
        ids = imap.uid_search(@uid_tracking_init_search)
      end
    else
      ids = imap.uid_search("NOT SEEN")
    end

    ids.each_slice(@fetch_count) do |id_set|
      items = imap.uid_fetch(id_set, ["BODY.PEEK[]", "UID"])
      items.each do |item|
        next unless item.attr.has_key?("BODY[]")
        mail = Mail.read_from_string(item.attr["BODY[]"])

        # Removed strip_attachments option because "mail.without_attachments!" was
        # stripping not just attachements but also files within a multipart MIME
        queue << parse_mail(mail)

        # Mark message as processed
        @uid_last_value = item.attr["UID"]
        if (@uid_tracking && @mark_read) || @delete || @expunge
          imap.uid_store(@uid_last_value, '+FLAGS', @delete || @expunge ? :Deleted : :Seen)
        end
        # Stop message processing if it is requested
        break if stop?
      end

      # Expunge deleted messages
      imap.expunge() if @expunge

      # Stop message fetching if it is requested
      break if stop?
    end

  rescue => e
    @logger.error("#{@user}@#{@host}:#{@port}/#{@folder}: Encountered error #{e.class}", :message => e.message, :backtrace => e.backtrace)
    # Do not raise error, check_mail will be invoked in the next run time

  ensure
    # Close the connection (and ignore errors)
    imap.close rescue nil
    imap.disconnect rescue nil

    # Always save @uid_last_value so when tracking is switched from
    # "NOT SEEN" to "UID" we will continue from first unprocessed message
    # Write only when the value has changed - makes logs less noisy
    if @uid_last_value and @uid_last_value != get_uid_last_value
      @logger.info("#{@user}@#{@host}:#{@port}/#{@folder}: Saving \"uid_last_value\": \"#{@uid_last_value}\"")
      File.write(@sincedb_path, @uid_last_value)
    end
  end

  # Summarize the bodies in the given list of parts
  # The purpose is to be able to debug this plugin's output without haven't to sift through
  # too much text.
  def summarize_bodies(parts)
    return parts.map do |p|
      p["body"] = "Body summary - length #{p["body"].length}"
      p
    end
  end

  # Constructs an array of attachement objects given a mail object
  def self.parse_attachments(mail)
    return mail.attachments.map do |a|
      {
        "filename" => a.filename, "content-id" => a.content_id,
        "content-type" => a.content_type,
        "content-disposition" => a.content_disposition,
        "content-transfer-encoding" => a.content_transfer_encoding,
        "body" => a.body.encoded
      }
    end
  end

  # Constructs an array of message objects given a mail object
  def self.parse_message(mail)
    proc_part = Proc.new { |p|
      if p.attachment?
        nil
      else
        # From experiments, content-id and content-disposition seems always nil
        # for the non-attachment parts so excluding here. Also excluding
        # content-transfer-encoding because the body here is provided decoded.
        # RFC about content-disposition https://tools.ietf.org/html/rfc1806
        { "content-type" => p.content_type, "body" => p.body.decoded }
      end
    }

    if mail.multipart?
      parts = mail.parts.map { |p|
        if p.multipart?
          # You are here bc this email is multipart/mixed with a nested
          # multipart/alternative or multipart/related
          p.parts.map { |pp|
            proc_part.call(pp)
          }
        else
          proc_part.call(p)
        end
      }

      return parts.flatten.compact
    else
      # No multipart message, just use the body as the event text
      return [proc_part.call(mail)]
    end
  end

  def parse_mail(mail)
    # Add a debug message so we can track what message might cause an error later
    @logger.trace? && @logger.trace("#{@user}@#{@host}:#{@port}/#{@folder}: Working with message_id", :message_id => mail.message_id)
    message = LogStash::Inputs::IMAP.parse_message(mail)
    message = @include_entire_body ? message : summarize_bodies(message)

    attachments = LogStash::Inputs::IMAP.parse_attachments(mail)
    attachments = @include_entire_body ? attachments : summarize_bodies(attachments)

    @codec.decode("Real message should replace this") do |event|
      # Tried to use json codec but ran into dependency issue
      # After experimentation, re-setting the "message" in the object seems to be
      # the easiest approach. Note that "event" here is a Logstash::Event object
      # which I think is defined in the logstash-core lib.
      event.set("message", message)

      # Use the 'Date' field as the timestamp
      event.timestamp = LogStash::Timestamp.new(mail.date.to_time)

      # Add fields: Add message.header_fields { |h| h.name=> h.value }
      mail.header_fields.each do |header|
        # 'header.name' can sometimes be a Mail::Multibyte::Chars, get it in String form
        name = @lowercase_headers ? header.name.to_s.downcase : header.name.to_s
        # Call .decoded on the header in case it's in encoded-word form.
        # Details at:
        #   https://github.com/mikel/mail/blob/master/README.md#encodings
        #   http://tools.ietf.org/html/rfc2047#section-2
        value = transcode_to_utf8(header.decoded.to_s)

        # Assume we already processed the 'date' above.
        next if name == "Date"

        case (field = event.get(name))
        when String
          # promote string to array if a header appears multiple times
          # (like 'received')
          event.set(name, [field, value])
        when Array
          field << value
          event.set(name, field)
        when nil
          event.set(name, value)
        end
      end

      # Add attachments
      if attachments && attachments.length > 0
        event.set('attachments', attachments)
      end

      # Add folder name
      event.set("folder", @folder)

      decorate(event)
      event
    end
  end

  def stop
    Stud.stop!(@run_thread)
    $stdin.close
  end

  private

  # transcode_to_utf8 is meant for headers transcoding.
  # the mail gem will set the correct encoding on header strings decoding
  # and we want to transcode it to utf8
  def transcode_to_utf8(s)
    unless s.nil?
      s.encode(Encoding::UTF_8, :invalid => :replace, :undef => :replace)
    end
  end
end
