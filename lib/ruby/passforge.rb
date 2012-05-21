#!/usr/bin/env ruby
require 'digest/sha1'
require 'bcrypt'

$DEBUG = true

module Passforge
  # The BCrypt library doesn't expose a way to correctly encode a user-provided
  # salt, so we access the private method. This may be unsafe.
  class OurBEngine < BCrypt::Engine
    def self.encode_salt(cost, bytes)
      # __bc_salt comes with this comment in the BCrypt source:
      # """
      # C-level routines which, if they don't get the right input, will crash
      # the hell out of the Ruby process.
      # """
      #
      # We try to validate our inputs so it is safe. This should really be done
      # in the BCrypt module instead.
      if not cost.is_a? Fixnum
        raise ArgumentError.new('cost must be a Fixnum')
      end
      if not bytes.is_a? String
        raise ArgumentError.new('bytes must be a String')
      end
      if bytes.length != Passforge::SALT_LENGTH
        msg = "bytes must have length == #{Passforge::SALT_LENGTH}"
        raise ArgumentError.new(msg)
      end

      __bc_salt(cost, bytes)
    end
  end

  class Error < StandardError; end
  class InvalidLength < Error; end

  class Passforge
    SALT_LENGTH = 16

    LEVEL_MAP = {'very low' => 12,
                 'low' => 13,
                 'medium' => 14,
                 'high' => 15,
                 'very high' => 16}

    def initialize
      raise NotImplementedError

    end

    def self.debug(message)
      STDERR.puts message if $DEBUG
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

    def self.generate(password, nickname, log_rounds, length=16)
      salt = salt_from_nickname(nickname)
      bsalt = OurBEngine.encode_salt(log_rounds, salt)
      debug "bcrypt salt: #{bsalt}"

      hashed = BCrypt::Engine.hash_secret(password, bsalt)
      debug "hashed: #{hashed}"

      derived = hashed[bsalt.length..-1]

      if derived.length < length
        raise InvalidLength.new("maximum generated length is #{derived.length}")
      end
      if length < 0
        raise InvalidLength.new('minimum generated length is 0')
      end

      return derived[0...length]
    end
  end
end

