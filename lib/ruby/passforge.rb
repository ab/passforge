#!/usr/bin/env ruby
# Passforge provides an algorithm for generating good passwords from a unique
# salt and a master passphrase. This is the official ruby implementation.
#
# Author::    Andy Brody <abrody@abrody.com>
# Copyright:: 2012
# License::   GNU General Public License version 3
#
# Dependencies: bcrypt-ruby <http://bcrypt-ruby.rubyforge.org/>

require 'digest/sha1'
require 'optparse'

require 'bcrypt'

$DEBUG = true

module Passforge
  # The BCrypt library doesn't expose a way to correctly encode a user-provided
  # salt, so we access the private method. This may be unsafe.
  class OurBEngine < BCrypt::Engine

    # Encode given bytes as a salt string that can be passed to hash_secret.
    # This mirrors the API provided by python-bcrypt's encode_salt.
    #
    # @param [Fixnum] log_rounds The log2(rounds) for bcrypt.
    # @param [String] bytes The salt as a string of bytes.
    #
    # __bc_salt comes with this comment in the BCrypt source:
    # """
    # C-level routines which, if they don't get the right input, will crash
    # the hell out of the Ruby process.
    # """
    # We try to validate our inputs so it is safe. This should really be done
    # in the BCrypt module instead.
    def self.encode_salt(log_rounds, bytes)
      if not log_rounds.is_a? Fixnum
        raise ArgumentError.new('log_rounds must be a Fixnum')
      end
      if not bytes.is_a? String
        raise ArgumentError.new('bytes must be a String')
      end
      if bytes.length != Passforge::SALT_LENGTH
        msg = "bytes must have length == #{Passforge::SALT_LENGTH}"
        raise ArgumentError.new(msg)
      end

      __bc_salt(log_rounds, bytes)
    end
  end

  class Error < StandardError; end
  class InvalidLength < Error; end

  def self.debug(message=nil, &blk)
    return unless $DEBUG
    if block_given?
      message = yield
    end
    STDERR.puts message
  end

  # Create a suitable salt from the user-supplied nickname.
  #
  # We are using truncated SHA1, but note that the cryptographic properties
  # of this function are actually not important. All we care about is that
  # the output length be SALT_LENGTH and that the output be unlikely to
  # collide with other commonly used nicknames.
  def self.salt_from_nickname(nick)
    digest = Digest::SHA1.digest(nick)
    raise Error.new('assertion failed') unless digest.length >= SALT_LENGTH
    return digest[0...SALT_LENGTH]
  end

  # Generate a password using bcrypt.
  #
  # @param [String] passphrase The master passphrase.
  # @param [String] nickname A unique label used to make the password unique.
  # @param [Fixnum] log_rounds The number of rounds of bcrypt to run.
  # @param [Fixnum] length The length of the generated password. Range: 0 to 31.
  # @return [String] A generated password resistant to brute force attacks.
  def self.generate(passphrase, nickname, log_rounds, length=16)
    salt = salt_from_nickname(nickname)
    bsalt = OurBEngine.encode_salt(salt, log_rounds)
    debug { "bcrypt salt: #{bsalt}" }

    hashed = BCrypt::Engine.hash_secret(passphrase, bsalt)
    debug { "hashed: #{hashed}" }

    derived = hashed[bsalt.length..-1]

    if derived.length < length
      raise InvalidLength.new("maximum generated length is #{derived.length}")
    end
    if length < 0
      raise InvalidLength.new('minimum generated length is 0')
    end

    return derived[0...length]
  end

  class Generator
    SALT_LENGTH = 16

    LEVEL_MAP = {'very low' => 12,
                 'low' => 13,
                 'medium' => 14,
                 'high' => 15,
                 'very high' => 16}

    def initialize(opts={})
      raise NotImplementedError

      @verbose = opts[:verbose]

      if opts[:password_file] == '-'
        f = STDIN
        vprint('reading password from first line of STDIN')
      else
        f = File.open(opts[:password_file], 'r')
        vprint('reading password from first line of ' + f.path.inspect)
      end
    end

    def vprint(message=nil, &blk)
      return unless @verbose
      if block_given?
        message = yield
      end
      STDERR.puts message
    end
  end

  def self.main
    options = {}

    options[:interactive] = true
    options[:verbose] = true

    optparse = OptionParser.new do |opts|
      opts.banner = <<-EOM
Usage: #{File.basename($0)} [options]
Options not given will be prompted interactively except in batch mode.

Options:
      EOM

      opts.on('-h', '--help', 'show this help message and exit') do
        puts opts
        return 0
      end

      opts.on('-p', '--password-file FILE',
              'read master password from FILE') do |filename|
        options[:password_file] = file
      end
      opts.on('-n', '--nickname TEXT',
              'per-site nickname used to determine unique password') do |nick|
        options[:nickname] = nick
      end
      opts.on('-r', '--rounds NUM', 'number of bcrypt rounds (2^NUM)') do |num|
        options[:rounds] = num
      end
      opts.on('-s', '--strengthening LEVEL',
              'number of bcrypt rounds by description') do |level|
        options[:strengthening] = level
      end
      opts.on('-l', '--length LENGTH', 'length of generated password') do |len|
        options[:length] = len
      end
      opts.on('-b', '--batch', 'non-interactive mode') do
        options[:interactive] = false
      end

      opts.on('-q', '--quiet', 'be less verbose') do
        options[:verbose] = false
      end
      opts.on('-d', '--debug', 'enable debug mode') do
        options[:debug] = true
      end
    end

    optparse.parse!

    g = Generator.new(options)
    g.run

    return 0
  end
end

if $0 == __FILE__
  puts 'lala'
  ret = Passforge.main
  begin
    exit(ret)
  rescue TypeError
    exit(0)
  end
end
