module LithiumSSO
  class CookieReader

    def initialize(secret_key)
      @secret_key = secret_key
    end

    def read(cookie)
      _, iv, encrypted = *cookie.match(/~2(.+)~(.+)/)

      raw_data = decrypt(encrypted, iv)

      lithium_version, server_id,
      timestamp1, timestamp2, # ???
      user_agent, referer, ip_address,
      lithium_domain, lithium_id,
      user_id, user_login, user_email, * = raw_data.gsub(/(^Li\|)|(iL$)/, '').split('|')

      {
        external_id: user_id,
        name: user_login,
        email: user_email
      }
    end

    private

    def decrypt(s, iv)
      s1 = s.gsub('-', '+').gsub('_', '/').gsub('.', '=')
      s2 = Base64.strict_decode64(s1)
      s3 = Mcrypt.new(:rijndael_128, :cbc, @secret_key.split.pack('H*'), iv).decrypt(s2)
      s4 = Zlib::Inflate.inflate(s3)
    end

  end
end
