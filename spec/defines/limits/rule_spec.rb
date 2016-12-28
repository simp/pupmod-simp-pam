require 'spec_helper'

describe 'pam::limits::rule' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|

      context "on #{os}" do
        let(:facts){ facts }

        let(:title){ 'test' }
        let(:params){{
          :domains => ['*'],
          :item => 'core',
          :value => 0,
          :type => '-',
          :order => 1
        }}

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to create_concat__fragment("pam_limits_rule_#{title}").with_content(
          /#{Regexp.escape(params[:domains].first)}\s#{params[:type]}\s#{params[:item]}\s#{params[:value]}/
        )}
      end
    end
  end
end
