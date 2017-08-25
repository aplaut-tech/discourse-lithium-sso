module LithiumSSO
  class SingleSignOn < DiscourseSingleSignOn

    attr_accessor :cookie

    def self.parse(cookie)
      sso = new
      sso.cookie = cookie

      secret_key = SiteSetting.lithium_sso_secret.presence or
        raise RuntimeError, "No SSO secret"
      cookie_reader = CookieReader.new(secret_key)
      decoded_hash = cookie_reader.read(cookie)

      ACCESSORS.each do |k|
        val = decoded_hash.with_indifferent_access[k]
        case
        when FIXNUMS.include?(k) then val = val.to_i
        when BOOLS.include?(k) then val = ["true", "false"].include?(val) ? val == "true" : nil
        end
        sso.send("#{k}=", val)
      end

      decoded_hash.each do |k, v|
        if field = k[/^custom\.(.+)$/, 1]
          sso.custom_fields[field] = v
        end
      end

      sso
    end

    def diagnostics
      ["cookie: #{cookie}", super].join(?\n)
    end

  end
end
