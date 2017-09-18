module LithiumSSO
  module SessionControllerOverride
    def self.override!
      SessionController.class_eval do

        def lithium_sso
          verbose_sso_log "Started SSO process"
          redirect_to SiteSetting.sso_url
        end


        def lithium_sso_login
          # Get Lithium cookie
          sso_cookie = cookies[SiteSetting.lithium_sso_login_cookie_name] or
            return render_sso_error(text: I18n.t("plugins.lithium_sso_no_cookie"), status: 400)

          # Read it
          sso = LithiumSSO::SingleSignOn.parse(sso_cookie)

          # Check if IP is banned
          if ScreenedIpAddress.should_block?(request.remote_ip)
            verbose_sso_log "IP address is blocked #{request.remote_ip}\n\n#{sso.diagnostics}"
            return render_sso_error(text: I18n.t("sso.unknown_error"), status: 500)
          end

          begin
            # Find existing user or create new one
            if (user = sso.lookup_or_create_user(request.remote_ip))

              # Is user requires approval?
              if SiteSetting.must_approve_users? && !user.approved?
                if SiteSetting.sso_not_approved_url.present?
                  redirect_to SiteSetting.sso_not_approved_url
                else
                  render_sso_error(text: I18n.t("sso.account_not_approved"), status: 403)
                end
                return
              # Is user inactive?
              elsif !user.active?
                activation = UserActivator.new(user, request, session, cookies)
                activation.finish
                session["user_created_message"] = activation.message
                redirect_to(users_account_created_path) and return
              else
                log_on_user user
                verbose_sso_log "User was logged on #{user.username}\n\n#{sso.diagnostics}"
              end

              # If it"s not a relative URL check the host
              return_path = session[:destination_url] || path("/")
              if return_path !~ /^\/[^\/]/
                begin
                  uri = URI(return_path)
                  unless SiteSetting.sso_allows_all_return_paths? || uri.host == Discourse.current_hostname
                    return_path = path("/")
                  end
                rescue
                  return_path = path("/")
                end
              end

              redirect_to return_path
            else
              render_sso_error(text: I18n.t("sso.not_found"), status: 500)
            end
          # We couldn"t create user
          rescue ActiveRecord::RecordInvalid => e
            verbose_sso_log <<~EOS.strip_heredoc
              Record was invalid: #{e.record.class.name} #{e.record.id}
              #{e.record.errors.to_h}

              Attributes:
              #{e.record.attributes.slice(*SingleSignOn::ACCESSORS.map(&:to_s))}

              SSO Diagnostics:
              #{sso.diagnostics}
            EOS

            text = I18n.t("sso.unknown_error")

            # If there"s a problem with the email we can explain that
            if (e.record.is_a?(User) && e.record.errors[:email].present?)
              if e.record.email.blank?
                text = I18n.t("sso.no_email")
              else
                text = I18n.t("sso.email_error", email: ERB::Util.html_escape(e.record.email))
              end
            end

            render_sso_error(text: text, status: 500)
          # Unexpected error just happened
          rescue => e
            message = "Failed to create or lookup user: #{e}."
            message << "\n\n" << "-" * 100 << "\n\n"
            message << e.backtrace.join("\n")

            Rails.logger.error(message)

            render_sso_error(text: I18n.t("sso.unknown_error"), status: 500)
          end
        end


        alias_method :discourse_sso, :sso
        def sso; lithium_sso? ? lithium_sso : discourse_sso end

        alias_method :discourse_sso_login, :sso_login
        def sso_login; lithium_sso? ? lithium_sso_login : discourse_sso_login end


        def destroy_with_lithium_cookie
          destroy_without_lithium_cookie
          Array.wrap(SiteSetting.lithium_sso_logout_cookie_names.try(:split, '|')).each do |cookie_name|
            cookies.delete(cookie_name, domain: :all)
          end
        end

        alias_method_chain :destroy, :lithium_cookie


        private

        def lithium_sso?
          SiteSetting.enable_sso? && SiteSetting.lithium_sso_mode?
        end

        def verbose_sso_log(message)
          Rails.logger.warn("Verbose SSO log: #{message}") if SiteSetting.verbose_sso_logging
        end

      end
    end
  end
end
