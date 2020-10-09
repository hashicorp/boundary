export const packageManagers = {
  homebrew: {
    label: 'Homebrew',
    url: '',
    commands: ['brew tap hashicorp/tap', 'brew install hashicorp/tap/boundary'],
  },
  ubuntu: {
    label: 'Ubuntu/Debian',
    commands: [
      'curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -',
      'sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"',
      'sudo apt-get update && sudo apt-get install boundary',
    ],
  },
  centos: {
    label: 'CentOS/RHEL',
    commands: [
      'sudo yum install -y yum-utils',
      'sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo',
      'sudo yum -y install boundary',
    ],
  },
  fedora: {
    label: 'Fedora',
    commands: [
      'sudo dnf install -y dnf-plugins-core',
      'sudo dnf config-manager --add-repo https://rpm.releases.hashicorp.com/fedora/hashicorp.repo',
      'sudo dnf -y install boundary',
    ],
  },
  amazonLinux: {
    label: 'Amazon Linux',
    commands: [
      'sudo yum install -y yum-utils',
      'sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo',
      'sudo yum -y install boundary',
    ],
  },
}

export const packageManagersByOs = {
  darwin: packageManagers.homebrew,
  linux: [
    packageManagers.ubuntu,
    packageManagers.centos,
    packageManagers.fedora,
    packageManagers.amazonLinux,
  ],
}

export const getStartedLinks = [
  {
    label: 'Install Boundary',
    href:
      'https://learn.hashicorp.com/tutorials/boundary/getting-started-install',
  },
  {
    label: 'Introduction to Boundary',
    href:
      'https://learn.hashicorp.com/tutorials/boundary/getting-started-intro',
  },
  {
    label: 'Start a Development Environment',
    href: 'https://learn.hashicorp.com/tutorials/boundary/getting-started-dev',
  },
]
