require 'spec_helper'

describe 'pam::access::rule' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) { facts }

        let(:title) { 'test' }
        let(:params) do
          {
            users: ['user1', 'user2'],
         origins: ['foo.bar.baz', 'bar.baz.foo'],
         order: 1
          }
        end

        it { is_expected.to compile.with_all_deps }

        it {
          is_expected.to create_concat__fragment("pam_access_rule_#{title}").with_content(
          %(+:#{params[:users].join(',')}:#{params[:origins].join(',')}\n),
        )
        }

        context 'with_comment' do
          let(:params) do
            {
              users: ['user1', 'user2'],
           origins: ['foo.bar.baz', 'bar.baz.foo'],
           order: 1,
           comment: "foo\nbar\nbaz"
            }
          end

          it {
            is_expected.to create_concat__fragment("pam_access_rule_#{title}").with_content(<<-EOM.gsub(%r{^\s+}, ''),
            # foo
            # bar
            # baz
            +:#{params[:users].join(',')}:#{params[:origins].join(',')}
            EOM
                                                                                           )
          }
        end
      end
    end
  end
end
