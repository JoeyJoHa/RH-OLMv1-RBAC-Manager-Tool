# OLMv1 RBAC Manager Tool

> **Disclaimer**: This repo contains AI-generated content using Cursor / Gemini AI.

A Python tool for extracting and managing RBAC permissions from operator bundles using the `opm` binary and interacting with OpenShift catalogs via the `catalogd` service. This tool automates the generation of secure RBAC resources and Helm values for OLMv1 operator deployments.

## Features

- **Catalog Discovery**: List and query OpenShift ClusterCatalogs for available operators
- **Configuration Management**: Generate and reuse configuration files for consistent deployments
- **Bundle Analysis**: Extract comprehensive metadata from operator bundle images using `opm render`
- **Smart RBAC Generation**: Auto-generate secure RBAC resources with intelligent permissions logic:
  - **Both `clusterPermissions` + `permissions`**: ClusterRoles + grantor Roles
  - **Only `permissions`**: Treat as ClusterRoles
  - **Only `clusterPermissions`**: ClusterRoles only
- **Permission Optimization**: Advanced permission deduplication eliminates redundant rules:
  - Removes duplicate permissions between ClusterRoles and Roles
  - Preserves resource-specific rules with `resourceNames`
  - Handles wildcard permissions intelligently
  - Reduces RBAC complexity and improves security posture
- **Enhanced YAML Formatting**: Clean formatting for readable Helm values with channel guidance:
  - Consistent flow-style arrays in both YAML and Helm outputs
  - Clean manifests without YAML anchors/aliases
  - Shared formatting logic for consistency
- **Security Best Practices**: Implements OLMv1 security patterns with comprehensive RBAC optimization
- **Comprehensive Output**: ServiceAccount, ClusterRole, ClusterRoleBinding, Role, RoleBinding manifests
- **Interactive Mode**: User-friendly prompts for catalog and package selection
- **Debug Logging**: Detailed logging for troubleshooting and analysis
- **Comprehensive Test Suite**: Extensive test coverage with consistent patterns:
  - Well-structured test methods using helper patterns
  - Consistent test execution across catalogd and OPM tests
  - Improved maintainability and reliability

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Tool Structure](#tool-structure)
- [Usage](#usage)
- [Configuration-Based Workflow](#configuration-based-workflow)
- [Permission Optimization](#permission-optimization)
- [Output](#output)
- [Examples](#examples)
- [Testing](#testing)
- [Integration](#integration)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## Prerequisites

### Required Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

### Required Tools

1. **opm**: Operator Package Manager CLI tool
   - Download from [operator-framework/operator-registry releases](https://github.com/operator-framework/operator-registry/releases)
   - Ensure `opm` is in your PATH

### Kubernetes Access (for catalogd features only)

- **Option 1**: Valid kubeconfig file configured for your OpenShift/Kubernetes cluster
- **Option 2**: Provide OpenShift URL and token for direct API access (`--openshift-url` and `--openshift-token`)

> **💡 Note**: Kubernetes access is only required for catalogd integration (listing catalogs, querying packages). The core `opm` command functionality works offline with just the bundle image URL.

## Installation

1. **Clone the repository**:

   ```bash
   git clone <repository-url>
   cd OLMv1-RBAC-Manager
   ```

2. **Create and activate a Python virtual environment** (recommended):

   ```bash
   # Create virtual environment
   python3 -m venv rbac-manager-env
   
   # Activate virtual environment
   # On Linux/macOS:
   source rbac-manager-env/bin/activate
   
   # On Windows:
   # rbac-manager-env\Scripts\activate
   ```

3. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Make the script executable**:

   ```bash
   chmod +x rbac-manager.py
   ```

> **💡 Tip**: Always use a virtual environment to avoid conflicts with system Python packages. To deactivate the virtual environment when done, simply run `deactivate`.

## Quick Start

### 1. List Available Catalogs

```bash
python3 rbac-manager.py list-catalogs \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token
```

### 2. Generate Configuration File

```bash
python3 rbac-manager.py catalogd --to-config \
  --catalog-name openshift-community-operators \
  --package argocd-operator \
  --channel alpha \
  --version 0.8.0 \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token \
  --skip-tls \
  --output ./config
```

### 3. Extract RBAC from Configuration

```bash
python3 rbac-manager.py opm \
  --config ./config/argocd-operator-rbac-config.yaml \
  --output ./rbac-output
```

### 4. Deploy RBAC Resources

```bash
kubectl apply -f rbac-output/argocd-operator-serviceaccount-*.yaml
kubectl apply -f rbac-output/argocd-operator-clusterrole-*.yaml
kubectl apply -f rbac-output/argocd-operator-clusterrolebinding-*.yaml
```

## Tool Structure

```
OLMv1-RBAC-Manager/
├── examples/                         # Example outputs and configs
│   ├── config/                       # Configuration file examples
│   ├── generated-files/              # Sample generated RBAC files
│   └── post-installation/            # Post-installation examples
├── rbac-manager/                     # Main tool package
│   ├── __init__.py                   # Package initialization
│   ├── help/                         # Help text files
│   │   ├── catalogd_examples_help.txt
│   │   ├── examples_help.txt
│   │   ├── generate_config_examples_help.txt
│   │   ├── list_catalogs_examples_help.txt
│   │   ├── main_help.txt
│   │   └── opm_examples_help.txt
│   └── libs/                         # Core libraries
│       ├── __init__.py
│       ├── catalogd/                 # Catalogd integration
│       │   ├── __init__.py
│       │   ├── cache.py              # Caching functionality
│       │   ├── client.py             # Client with error handling
│       │   ├── parser.py             # Data extraction
│       │   ├── service.py            # Service layer
│       │   └── session.py            # HTTP session management
│       ├── core/                     # Core utilities
│       │   ├── __init__.py
│       │   ├── auth.py               # Authentication
│       │   ├── config.py             # Configuration management
│       │   ├── constants.py          # Constants
│       │   ├── exceptions.py         # Custom exceptions
│       │   ├── protocols.py          # Type protocols
│       │   └── utils.py              # Utilities
│       ├── opm/                      # OPM integration
│       │   ├── __init__.py
│       │   ├── base_generator.py     # Base RBAC generator
│       │   ├── client.py             # OPM execution
│       │   ├── helm_generator.py     # Helm values generation
│       │   ├── processor.py          # Bundle processing
│       │   └── yaml_generator.py     # YAML generation
│       ├── help_manager.py           # Help system
│       └── main_app.py               # Main application
├── tests/                            # Test suite
│   ├── test_catalogd.py
│   ├── test_constants.py
│   ├── test_opm.py
│   ├── test_workflow.py
│   └── results/                      # Test results
├── rbac-manager.py                   # CLI entry point
├── requirements.txt                  # Python dependencies
└── README.md                         # This documentation
```

## Usage

The RBAC Manager uses a subcommand structure with four main commands:

### Commands Overview

| Command | Purpose | Requires Cluster Access |
|---------|---------|------------------------|
| `list-catalogs` | List available ClusterCatalogs | Yes |
| `catalogd` | Query packages and generate configs | Yes |
| `generate-config` | Create blank config template | No |
| `opm` | Extract RBAC from bundles | No |

### Global Help

```bash
python3 rbac-manager.py --help
```

### 1. List ClusterCatalogs

List all available ClusterCatalogs in your cluster:

```bash
python3 rbac-manager.py list-catalogs \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~token
```

**Available flags:**

- `--openshift-url URL`: OpenShift cluster URL
- `--openshift-token TOKEN`: OpenShift authentication token  
- `--skip-tls`: Skip TLS verification
- `--debug`: Enable debug logging
- `--examples`: Show usage examples

### 2. Query Catalogd Service

Query the catalogd service for package information:

**Interactive catalog selection:**

```bash
python3 rbac-manager.py catalogd \
  --package quay-operator \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~token \
  --skip-tls
```

**Query specific catalog:**

```bash
python3 rbac-manager.py catalogd \
  --catalog-name openshift-community-operators \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~token \
  --skip-tls
```

**Query specific package channels:**

```bash
python3 rbac-manager.py catalogd \
  --catalog-name openshift-community-operators \
  --package argocd-operator \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~token \
  --skip-tls
```

**Get detailed version metadata:**

```bash
python3 rbac-manager.py catalogd \
  --catalog-name openshift-community-operators \
  --package argocd-operator \
  --channel alpha \
  --version 0.8.0 \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~token \
  --skip-tls
```

### 3. Generate Configuration Files

**Generate blank config template (no auth required):**

```bash
# Generate to stdout
python3 rbac-manager.py generate-config

# Generate to file
python3 rbac-manager.py generate-config --output ./config
```

**Generate config with real cluster data:**

```bash
python3 rbac-manager.py catalogd --to-config \
  --catalog-name openshift-community-operators \
  --package argocd-operator \
  --channel alpha \
  --version 0.8.0 \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~token \
  --skip-tls \
  --output ./config
```

### 4. Extract Bundle Metadata and Generate RBAC

**Using configuration file (YAML manifests):**

```bash
python3 rbac-manager.py opm \
  --config nginx-ingress-operator-rbac-config.yaml
```

**Using configuration file (Helm values):**

Modify config file to set `output.type: helm`, then:

```bash
python3 rbac-manager.py opm \
  --config nginx-ingress-operator-rbac-config.yaml
```

**Direct bundle extraction (YAML manifests):**

```bash
python3 rbac-manager.py opm \
  --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9...
```

**Generate Helm values:**

```bash
python3 rbac-manager.py opm \
  --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9... \
  --helm
```

**With custom namespace:**

```bash
python3 rbac-manager.py opm \
  --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9... \
  --namespace quay-operator
```

**Save to files:**

```bash
python3 rbac-manager.py opm \
  --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9... \
  --output ./rbac-files
```

**With registry authentication:**

```bash
python3 rbac-manager.py opm \
  --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9... \
  --registry-token your-registry-token
```

## Configuration-Based Workflow

The recommended workflow uses configuration files for consistency and repeatability:

```bash
# Step 1: List available catalogs
python3 rbac-manager.py list-catalogs \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~token

# Step 2: Generate configuration with real cluster data  
python3 rbac-manager.py catalogd --to-config \
  --catalog-name openshift-community-operators \
  --package argocd-operator \
  --channel alpha \
  --version 0.8.0 \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~token \
  --skip-tls \
  --output ./config

# Step 3: Extract RBAC using configuration
python3 rbac-manager.py opm \
  --config ./config/argocd-operator-rbac-config.yaml

# Step 4: Deploy RBAC resources
kubectl apply -f argocd-operator-serviceaccount-*.yaml
kubectl apply -f argocd-operator-clusterrole-*.yaml
kubectl apply -f argocd-operator-clusterrolebinding-*.yaml
kubectl apply -f argocd-operator-role-*.yaml
kubectl apply -f argocd-operator-rolebinding-*.yaml
```

### Configuration File Format

```yaml
operator:
  name: argocd-operator
  package: argocd-operator
  version: 0.8.0
  channel: alpha
  catalog: openshift-community-operators

bundle:
  image: quay.io/operatorhubio/argocd-operator@sha256:abc123...

namespace: argocd-operator

output:
  type: yaml  # or 'helm'
  directory: ./rbac-output

registry:
  skip_tls: false
  token: ""  # Optional registry token
```

## Permission Optimization

The RBAC Manager implements intelligent permission optimization to create clean, secure RBAC configurations.

### Permission Deduplication Logic

1. **Duplicate Detection**: Identifies when Role permissions are already covered by broader ClusterRole permissions
2. **Wildcard Handling**: Recognizes when ClusterRole wildcard permissions (`verbs: ['*']`) supersede specific Role permissions
3. **Resource-Specific Preservation**: Keeps Role rules with `resourceNames` even when broader ClusterRole permissions exist
4. **Multi-Stage Filtering**: Applies optimization at multiple stages for comprehensive cleanup

### Example

**Before Optimization** (redundant):

```yaml
# ClusterRole
- apiGroups: ['']
  resources: [configmaps, serviceaccounts, services]
  verbs: ['*']

# Role (DUPLICATES!)
- apiGroups: ['']
  resources: [configmaps]
  verbs: [create, delete, get, list, patch, update, watch]
- apiGroups: ['']  
  resources: [serviceaccounts]
  verbs: [create, list, watch]
```

**After Optimization** (clean):

```yaml
# ClusterRole (unchanged)
- apiGroups: ['']
  resources: [configmaps, serviceaccounts, services]
  verbs: ['*']

# Role (only resource-specific permissions remain)
- apiGroups: ['']
  resources: [serviceaccounts]
  verbs: [delete, get, patch, update]
  resourceNames: [operator-controller-manager]
```

### Benefits

- **Enhanced Security**: Eliminates permission redundancy and potential conflicts
- **Reduced Complexity**: Fewer RBAC rules to manage and audit
- **Precise Permissions**: Preserves granular resource-specific access controls

## Output

### Generated Files

#### YAML Manifests (default)

- `{operator-name}-serviceaccount-{timestamp}.yaml`: ServiceAccount for the operator installer
- `{operator-name}-clusterrole-{timestamp}.yaml`: ClusterRoles for operator management
- `{operator-name}-clusterrolebinding-{timestamp}.yaml`: ClusterRoleBindings
- `{operator-name}-role-{timestamp}.yaml`: Namespace-scoped Roles (when applicable)
- `{operator-name}-rolebinding-{timestamp}.yaml`: RoleBindings
- `{operator-name}-{timestamp}.yaml`: Complete manifest with all resources

#### Helm Values (`--helm` flag)

- **Security Notice Header**: Post-installation hardening instructions
- **Operator Configuration**: Package name, version, channel information
- **ServiceAccount**: Configuration for installer service account
- **ClusterRoles**: Operator management + grantor permissions
- **Roles**: Grantor permissions (when both permission types exist)
- **Mixed YAML Style**: Block style with flow arrays for readability

## Examples

The `examples/` directory contains sample outputs and configurations:

- **`config/`**: Example configuration files for different operators
- **`generated-files/`**: Sample RBAC manifests generated by the tool
- **`post-installation/`**: Examples of post-installation RBAC modifications

### Example 1: Quick RBAC Extraction

```bash
# Extract RBAC directly from a bundle image
python3 rbac-manager.py opm \
  --image quay.io/openshift-community-operators/argocd-operator@sha256:abc123... \
  --namespace argocd-operator \
  --output ./rbac-files
```

### Example 2: Generate Helm Values

```bash
# Generate Helm values for use with OLMv1 Helm Chart
python3 rbac-manager.py opm \
  --image quay.io/openshift-community-operators/argocd-operator@sha256:abc123... \
  --helm \
  --output ./helm-values
```

### Example 3: Configuration-Based Deployment

```bash
# Step 1: Create configuration
python3 rbac-manager.py catalogd --to-config \
  --catalog-name openshift-community-operators \
  --package quay-operator \
  --channel stable-3.10 \
  --version 3.10.13 \
  --openshift-url https://api.cluster.com:6443 \
  --openshift-token sha256~token \
  --output ./config

# Step 2: Generate RBAC
python3 rbac-manager.py opm \
  --config ./config/quay-operator-rbac-config.yaml \
  --output ./rbac-output

# Step 3: Deploy
kubectl apply -f rbac-output/
```

### Example 4: Debug Mode

```bash
# Enable detailed logging for troubleshooting
python3 rbac-manager.py opm \
  --image your-bundle-image \
  --debug
```

## Testing

The project includes a comprehensive test suite:

```bash
# Run all tests
python3 -m pytest tests/

# Run specific test file
python3 -m pytest tests/test_catalogd.py

# Run with verbose output
python3 -m pytest tests/ -v

# Run with coverage
python3 -m pytest tests/ --cov=rbac-manager
```

### Test Structure

- `test_catalogd.py`: Tests for catalogd integration
- `test_opm.py`: Tests for OPM functionality
- `test_workflow.py`: End-to-end workflow tests
- `test_constants.py`: Constants validation tests

## Integration

### With OLMv1 Helm Chart

The generated Helm values files work seamlessly with the [OLMv1 Helm Chart](https://github.com/yourusername/OLMv1-Helm-Chart):

```bash
# Generate Helm values
python3 rbac-manager.py opm \
  --image your-bundle-image \
  --helm \
  --output ./helm-values

# Deploy using Helm Chart
helm install my-operator olmv1/olmv1-operator \
  -f helm-values/values-my-operator.yaml
```

### With GitOps

Store generated configurations in Git for GitOps workflows:

```bash
# Generate configuration
python3 rbac-manager.py catalogd --to-config \
  --catalog-name openshift-community-operators \
  --package argocd-operator \
  --channel alpha \
  --version 0.8.0 \
  --openshift-url https://api.cluster.com:6443 \
  --openshift-token sha256~token \
  --output ./gitops/config

# Generate RBAC manifests
python3 rbac-manager.py opm \
  --config ./gitops/config/argocd-operator-rbac-config.yaml \
  --output ./gitops/manifests

# Commit to Git
git add gitops/
git commit -m "Add ArgoCD operator RBAC configuration"
```

## Troubleshooting

### Common Issues

#### 1. "opm binary not found"

**Solution:**
- Install opm CLI tool from [operator-framework releases](https://github.com/operator-framework/operator-registry/releases)
- Ensure opm is in your PATH

#### 2. "Failed to establish port-forward"

**Solution:**
- Ensure kubeconfig is configured and connected to your cluster, OR
- Use `--openshift-url` and `--openshift-token` for direct API access
- Check that catalogd service exists in openshift-catalogd namespace

#### 3. "No ClusterCatalogs found"

**Solution:**
- Verify you're connected to an OpenShift cluster with OLMv1
- Check cluster permissions for listing ClusterCatalogs
- Try using direct API access with `--openshift-url` and `--openshift-token`

#### 4. "Image appears to be an index image"

**Solution:**
- Create a ClusterCatalog resource first
- Use `catalogd` command instead of `opm` command for index images

#### 5. "Kubernetes client not initialized"

**Solution:**
- Either configure kubeconfig, OR
- Use `--openshift-url https://api.cluster.com:6443 --openshift-token <token>`

### Debug Logging

Enable detailed logging with the `--debug` flag:

```bash
python3 rbac-manager.py opm --debug --image your-bundle-image
```

### Skip TLS Verification

For development environments with self-signed certificates:

```bash
python3 rbac-manager.py catalogd --skip-tls \
  --openshift-url https://api.dev-cluster.local:6443 \
  --openshift-token your-token
```

## Related Projects

- **[OLMv1 Helm Chart](https://github.com/yourusername/OLMv1-Helm-Chart)**: Helm chart for simplified operator deployment
- **[OLMv1 Case Study](https://github.com/yourusername/OLMv1-CaseStudy)**: Examples and documentation for OLMv1 deployments

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add/update tests
5. Ensure all tests pass
6. Submit a pull request

### Development Setup

```bash
# Clone and setup
git clone <repository-url>
cd OLMv1-RBAC-Manager
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
python3 -m pytest tests/

# Run linting (if configured)
flake8 rbac-manager/
```

## License

[Specify your license here]

## Acknowledgments

- OpenShift Operator Framework team for OLMv1
- Kubernetes community for operator patterns
- Contributors to this project

## Support

For issues and questions:

- Open an issue in this repository
- Check the [OLMv1 documentation](https://github.com/openshift/operator-framework-operator-controller)
- Review the [Case Study repository](https://github.com/yourusername/OLMv1-CaseStudy) for examples

---

**Made with ❤️ for the Kubernetes community**
