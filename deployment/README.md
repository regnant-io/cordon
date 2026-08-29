# Deployment

Reference material for running Cordon outside a development machine. Each
artefact here is a starting point that expects editing, not a drop-in.

## Contents

| Path | Purpose |
|---|---|
| `configs/` | Generated configuration for each deployment mode. |
| `docker/` | Prometheus and Grafana provisioning for the Compose stack. |
| `kubernetes/` | A StatefulSet for Vault and Sovereign Cloud modes. |
| `ansible/` | A playbook and systemd unit for bare-metal and VM deployment. |
| `terraform/` | Infrastructure for a confidential-computing VM. |

## Configuration

`configs/` is generated, and regenerating it is the right way to update it:

```bash
for mode in light island vault sovereign_cloud dark; do
  cordon default-config --mode "$mode" > "deployment/configs/cordon-$mode.toml"
done
```

Every generated file contains `REPLACE_ME` placeholders that must be filled in,
and every mode other than Light contains a commented `[attestation.expected]`
block that **must** be populated before the node will start.

Check a configuration before deploying it:

```bash
cordon doctor --config deployment/configs/cordon-vault.toml
```

`doctor` reports the posture the configuration will actually deliver, not the
one it claims — an unenrolled client registry, a missing client CA, or a TPM
that is configured but unreachable each show up here rather than at 3am.

## What every mode above Light requires

1. **A Client Master Key**, on a memory-backed filesystem the node reads through
   `CORDON_CMK_FILE`. Without one the node refuses to start, because an audit
   log it signs with a key it generated itself proves nothing to anyone else.

2. **A client CA and client certificates.** Identity comes from the certificate;
   `--no-tls` is refused.

3. **A reachable TPM**, with a provisioned attestation key in
   `CORDON_TPM_AK_CTX`. Cordon does not fall back to a software measurement.

4. **Pinned expected measurements.** Start the node once on hardware you trust,
   read them, review them, and commit them:

   ```bash
   cordon attest --pin --api https://node:8443 >> /etc/cordon/cordon.toml
   ```

5. **An enrolled client registry** at `client_registry_path`. Once it enrols
   anyone, unenrolled clients are denied.

## Metrics

Cordon serves `/metrics` only to a peer on loopback, and that is not relaxed for
container or cluster networks: the output names clients, models, and traffic
volumes.

Scrape it from something that shares the node's network namespace — a Compose
service with `network_mode: "service:cordon"`, or a sidecar container in the
same Kubernetes pod. Both arrangements are set up in the files here.

## Model weights

Connected modes can fetch models directly:

```bash
cordon pull Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M
```

Air-gapped modes take them as encrypted bundles from physical media:

```bash
# On the operator's machine, with the CMK
cordon-provision encrypt --weights ./weights --cmk-file ./cmk \
  --bundle-id qwen2.5-7b --client-id operator \
  --model-name "Qwen2.5 7B" --output ./bundle

# On the node, after transfer
cordon-provision verify --bundle /var/lib/cordon/bundles/qwen2.5-7b \
  --cmk-file /run/cordon/cmk --client-id operator
```

Set `model_store.staging_dir` to a `tmpfs` mount so the decrypted weights that
exist during a model load never reach persistent storage.
