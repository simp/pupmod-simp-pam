require 'spec_helper'

describe 'pam::access' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|

      context "on #{os}" do
        let(:facts){ facts }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_concat('/etc/security/access.conf') }
        it { is_expected.to create_pam__access__rule('default_deny').with({
            :permission => '-',
            :users      => ['ALL'],
            :origins    => ['ALL'],
            :order      => 9999999999
          })
        }
        it { is_expected.to create_pam__access__rule('allow_local_root').with({
            :permission => '+',
            :users      => ['root'],
            :origins    => ['LOCAL'],
            :order      => 1
          })
        }
      end

      context 'create pam::access::rule resources with an iterator' do
        context 'with a well-formatted data structure' do
          let(:hieradata) { 'pam__access__users' }
          it { is_expected.to create_pam__access__rule('rule_vagrant').with({
            :users      => ['vagrant'],
            :origins    => ['ALL'],
            :permission => '+'
          }) }
          it { is_expected.to create_pam__access__rule('rule_(simp)').with({
            :users      => ['(simp)'],
            :origins    => ['ALL'],
            :permission => '+'
          }) }
          it { is_expected.to create_pam__access__rule('rule_test').with({
            :users      => ['test'],
            :origins    => ['192.168.0.1/24'],
            :permission => '+'
          }) }
          it { is_expected.to create_pam__access__rule('rule_baddude').with({
            :users      => ['baddude'],
            :origins    => ['ALL'],
            :permission => '-'
          }) }
        end
        context 'without a defaults hash' do
          let(:hieradata) { 'pam__access__users_no_defaults' }
          it { is_expected.to create_pam__access__rule('rule_vagrant').with({
            :users      => ['vagrant'],
            :origins    => ['ALL'],
            :permission => '+'
          }) }
          it { is_expected.to create_pam__access__rule('rule_(simp)').with({
            :users      => ['(simp)'],
            :origins    => ['ALL'],
            :permission => '+'
          }) }
          it { is_expected.to create_pam__access__rule('rule_test').with({
            :users      => ['test'],
            :origins    => ['192.168.0.1/24'],
            :permission => '+'
          }) }
          it { is_expected.to create_pam__access__rule('rule_baddude').with({
            :users      => ['baddude'],
            :origins    => ['ALL'],
            :permission => '-'
          }) }
        end
      end

    end
  end
end
