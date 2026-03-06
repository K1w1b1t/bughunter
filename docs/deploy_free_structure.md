# Deploy na Oracle Cloud Always Free usando Terraform + GitHub Actions

Este guia mostra como automatizar build e deploy do container do projeto para a Oracle Cloud (Always Free), provisionar infraestrutura básica com Terraform e usar GitHub Actions como CI/CD. O foco é: `GitHub Actions` -> `OCIR` (Oracle Container Registry) -> `Compute Instance` Always Free que executa o container. Todas as outras opções foram removidas.

Visão geral
- Pipeline: push para `main` → GitHub Actions constrói imagem Docker → envia para OCIR → faz SSH na instância Oracle e atualiza o container (pull + restart).  
- Infraestrutura: provisionada por Terraform (VCN, subnet, internet gateway, route table, security list, compute instance).  
- Segredos/credenciais: mantidos no `GitHub Secrets` (API key da OCI, OCIR auth token, SSH key privada para a instância).

Pré-requisitos
- Conta Oracle Cloud (crie em https://cloud.oracle.com) e habilite recursos Always Free.  
- GitHub repo com este código.  
- `terraform` instalado localmente para testes (opcional).  
- `oci` CLI opcional para debug.  

Passo 1 — Criar conta e preparar credenciais OCI
1. Crie a conta Oracle e confirme e-mail/CPF conforme o processo da Oracle.  
2. Anote seu `Tenancy OCID`, `User OCID` e `Region` (disponíveis no console, canto superior direito).  
3. Gere uma API Key para o seu usuário OCI:
   - No Console: Menu → Identity → Users → selecione seu usuário → API Keys → Add API Key.  
   - Você pode gerar o par RSA localmente: `ssh-keygen -t rsa -b 2048 -m PEM -f oci_api_key.pem` e envie o conteúdo de `oci_api_key.pem.pub` ao console.  
   - Anote a `fingerprint` mostrada após upload da chave.  
4. Recupere seu `tenancy namespace` (usado no OCIR): rode `oci os ns get` se tiver `oci` CLI, ou pegue em Console → Developer Services → Container Registry → Namespace.

Passo 2 — Criar um repositório OCIR (opcional)
- OCIR geralmente aceita push direto para `<region-key>.ocir.io/<namespace>/<repo>`. Você pode criar um repo via Terraform/OCI, mas não é obrigatório: ao empurrar a imagem, o repositório será criado implicitamente.

Passo 3 — Preparar Terraform (provisionamento da VM Always Free)
Observação: alguns shapes podem variar; escolha um shape Always Free elegível ao criar a variável `instance_shape`.

Exemplo mínimo de `terraform/main.tf` (adaptar antes de aplicar):
```hcl
terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 4.0"
    }
  }
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}

variable "tenancy_ocid" {}
variable "user_ocid" {}
variable "fingerprint" {}
variable "private_key_path" {}
variable "region" { default = "us-ashburn-1" }
variable "ssh_public_key" {}
variable "instance_shape" { default = "VM.Standard.E2.1.Micro" }

resource "oci_core_vcn" "vcn" {
  cidr_block = "10.0.0.0/16"
  display_name = "hunterops-vcn"
  compartment_id = data.oci_identity_tenancy.tenancy.id
}

# ... criar internet gateway, route table, subnet, security list (abrir 22, 80/443 conforme necessário)

resource "oci_core_instance" "vm" {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id = data.oci_identity_tenancy.tenancy.id
  shape = var.instance_shape
  display_name = "hunterops-vm"

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data = base64encode("#!/bin/bash\napt-get update && apt-get install -y docker.io && systemctl enable docker \n# login to OCIR will be done on deploy via SSH\n")
  }
  create_vnic_details {
    subnet_id = oci_core_subnet.subnet.id
    assign_public_ip = true
  }
}

data "oci_identity_tenancy" "tenancy" {}
data "oci_identity_availability_domains" "ads" {}

output "instance_public_ip" {
  value = oci_core_instance.vm.public_ip
}
```

Notas Terraform
- Complete o arquivo com `oci_core_internet_gateway`, `oci_core_route_table`, `oci_core_subnet`, `oci_core_security_list` e vincule-os ao `vcn`.  
- Não deixe segredos em arquivos .tf; passe `private_key_path` localmente ou via CI secrets quando usar `terraform apply` no Actions.

Passo 4 — Preparar a instância para rodar o container
- O cloud-init acima instala Docker; crie um pequeno script `run_container.sh` que faz `docker login` no OCIR, `docker pull` e `docker run` com volumes montados. Esse script será invocado via SSH pelo GitHub Actions após push da imagem.

Exemplo `run_container.sh` (na instância, executado por Actions via SSH):
```bash
#!/bin/bash
OCIR_REGISTRY="$OCIR_REGISTRY" # ex: iad.ocir.io/tenancy-namespace
REPO="$OCIR_REPO" # ex: hunterops/hunterops
TAG="$1"
USER="$OCIR_USER" # tenancy-namespace/username
PASS="$OCIR_AUTH_TOKEN"

echo "$PASS" | docker login $OCIR_REGISTRY -u "$USER" --password-stdin
docker pull $OCIR_REGISTRY/$REPO:$TAG
docker stop hunterops || true
docker rm hunterops || true
docker run -d --name hunterops --restart unless-stopped \
  -v /home/opc/hunterops/data:/app/data \
  -v /home/opc/hunterops/config:/app/config:ro \
  $OCIR_REGISTRY/$REPO:$TAG
```

Passo 5 — GitHub Actions (CI/CD)
- Crie os seguintes `Secrets` no GitHub repo (Settings → Secrets):
  - `OCI_TENANCY_OCID` (tenancy OCID)
  - `OCI_USER_OCID` (user OCID)
  - `OCI_REGION` (ex: `us-ashburn-1`)
  - `OCI_PRIVATE_KEY` (conteúdo da sua chave privada API, PEM)
  - `OCI_FINGERPRINT` (fingerprint da chave API)
  - `OCI_NAMESPACE` (OCIR namespace)
  - `OCIR_AUTH_TOKEN` (auth token para OCIR login — pode ser gerado no console como "Auth Token")
  - `OCIR_USERNAME` (formato: `<namespace>/<username>`, usado para docker login)
  - `SSH_PRIVATE_KEY` (chave privada para SSH na instância criada)
  - `SSH_USER` (ex: `opc`)
  - `INSTANCE_IP` (IP público da instância — se for dinâmico, recupere via Terraform output)

Exemplo de workflow `.github/workflows/deploy.yml`:
```yaml
name: CI/CD -> Oracle Always Free

on:
  push:
    branches: [ main ]

env:
  OCIR_REGISTRY: ${{ secrets.OCI_REGION }}.ocir.io/${{ secrets.OCI_NAMESPACE }}
  OCIR_REPO: hunterops/hunterops

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up QEMU (optional for multi-arch)
        uses: docker/setup-qemu-action@v2

      - name: Build and tag image
        run: |
          IMAGE=${{ env.OCIR_REGISTRY }}/${{ env.OCIR_REPO }}:${{ github.sha }}
          docker build -t $IMAGE .

      - name: Login to OCIR
        env:
          OCIR_USER: ${{ secrets.OCIR_USERNAME }}
          OCIR_PASS: ${{ secrets.OCIR_AUTH_TOKEN }}
          OCIR_REG: ${{ env.OCIR_REGISTRY }}
        run: |
          echo "$OCIR_PASS" | docker login $OCIR_REG -u "$OCIR_USER" --password-stdin

      - name: Push image
        run: |
          IMAGE=${{ env.OCIR_REGISTRY }}/${{ env.OCIR_REPO }}:${{ github.sha }}
          docker push $IMAGE

      - name: Notify deploy job
        run: echo "image=${{ env.OCIR_REGISTRY }}/${{ env.OCIR_REPO }}:${{ github.sha }}" >> $GITHUB_OUTPUT

  deploy:
    needs: build-and-push
    runs-on: ubuntu-latest
    steps:
      - name: Wait for image
        run: echo "Deploying"

      - name: Setup SSH key
        uses: webfactory/ssh-agent@v0.7.0
        with:
          ssh-private-key: ${{ secrets.SSH_PRIVATE_KEY }}

      - name: Pull & run on remote
        env:
          OCIR_REGISTRY: ${{ env.OCIR_REGISTRY }}
          OCIR_REPO: ${{ env.OCIR_REPO }}
          OCIR_USER: ${{ secrets.OCIR_USERNAME }}
          OCIR_AUTH_TOKEN: ${{ secrets.OCIR_AUTH_TOKEN }}
        run: |
          TAG=${{ github.sha }}
          ssh -o StrictHostKeyChecking=no ${{ secrets.SSH_USER }}@${{ secrets.INSTANCE_IP }} "mkdir -p ~/hunterops && cat > ~/hunterops/run_container.sh <<'EOF'\n$(sed -n '1,200p' <<'RUNSCRIPT'
#!/bin/bash
OCIR_REGISTRY="$OCIR_REGISTRY"
REPO="$OCIR_REPO"
TAG="$TAG"
USER="$OCIR_USER"
PASS="$OCIR_AUTH_TOKEN"
echo "$PASS" | docker login $OCIR_REGISTRY -u "$USER" --password-stdin
docker pull $OCIR_REGISTRY/$REPO:$TAG
docker stop hunterops || true
docker rm hunterops || true
docker run -d --name hunterops --restart unless-stopped \
  -v /home/opc/hunterops/data:/app/data \
  -v /home/opc/hunterops/config:/app/config:ro \
  $OCIR_REGISTRY/$REPO:$TAG
RUNSCRIPT
EOF
" && ssh ${{ secrets.SSH_USER }}@${{ secrets.INSTANCE_IP }} "chmod +x ~/hunterops/run_container.sh && ~/hunterops/run_container.sh"

```

Observações sobre o workflow
- O job `build-and-push` gera a imagem e a empurra ao OCIR.  
- O job `deploy` faz SSH na instância e executa o script que atualiza o container.  
- Alternativa segura: usar `oci` CLI e recursos de Vault; aqui optamos por um fluxo simples via SSH.

Passo 6 — Provisionar via GitHub Actions (Terraform)
- Você pode executar `terraform apply` diretamente no Actions (job separado) usando os mesmos secrets (`OCI_*`). Ao usar Terraform no Actions, passe a chave privada da API (como `OCI_PRIVATE_KEY`) via secret e execute `terraform init`/`apply -auto-approve`.
- Recomendo: testar `terraform plan` localmente antes de aplicar pelo Actions.

Segurança e boas práticas
- Nunca guarde chaves privadas no repositório. Use `GitHub Secrets`.  
- Para OCIR, prefira gerar `Auth Token` (console) especificamente para docker push e mantenha-o rotacionado.  
- Considere usar Oracle Vault para armazenar segredos e recuperar via `oci` CLI na instância em produção.

Checklist final e resumo rápido
- Criar conta OCI e API key; obter tenancy namespace.  
- Adicionar secrets no GitHub (OCI API key, OCIR token, SSH key, etc.).  
- Ajustar `terraform/main.tf` e rodar `terraform apply` (ou criar job no Actions).  
- Testar GitHub Actions: push para `main` e validar que a instância é atualizada.

Próximos passos que eu posso fazer por você
- Gerar arquivos práticos: `terraform/` completo (VCN, subnet, IG, route table, security list, instance) e `.github/workflows/deploy.yml` adaptado ao repositório.  
- Testar localmente (posso instruir os comandos para rodar).  

---
Recomenda-se revisar cada trecho de Terraform e Actions antes de rodar em produção; ajuste shapes Always Free e regras de firewall conforme sua política de OPSEC.

