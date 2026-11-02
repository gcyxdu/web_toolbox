"""Built-in PyTorch learning modules behind the VisualFL event contract.

The historical engine ID stays stable for saved experiments.
"""
from __future__ import annotations

import copy
import importlib.util
import logging
import random
import time
from types import SimpleNamespace

import numpy as np

from backend.config.methods import defaults
from backend.datasets.partition import prepare_data
from backend.config.schema import ExperimentConfig
from backend.learning import UPSTREAM_REVISION
from backend.datasets.catalog import DATASETS
from backend.system.device import training_device
from backend.engines.base import Cancelled, Emit


def make_args(config: ExperimentConfig, client: dict | None = None, device: str | None = None) -> SimpleNamespace:
    settings = client or {"learning_rate": config.learning_rate, "local_steps": config.local_steps,
                          "attack_params": {**defaults("attack", config.attack), **config.attack_params}}
    attack_params = copy.deepcopy(settings["attack_params"])
    for key in ("trigger_size", "target_label"):
        if key in attack_params:
            attack_params[key] = int(attack_params[key])
    if config.attack == "BadNets":
        attack_params.update(attack_model="all2one", attack_strategy="continuous", attack_start_epoch=0,
                             single_epoch=0, poison_frequency=1, source_label=1)
    defense_params = copy.deepcopy(config.defense_settings())
    if config.defense == "Krum":
        defense_params = {"enable_check": True}
    return SimpleNamespace(
        model=config.model, algorithm=config.algorithm, dataset=config.dataset, num_dims=DATASETS[config.dataset]["shape"][0], num_channels=DATASETS[config.dataset].get("channels",1),
        input_dim=DATASETS[config.dataset]['features'], num_classes=DATASETS[config.dataset]['classes'],
        mean=(0.,)*DATASETS[config.dataset].get("channels",1), std=(1.,)*DATASETS[config.dataset].get("channels",1), device=device or training_device(), num_workers=0, num_clients=config.participants,
        num_adv=int(config.defense_settings().get("byzantine_budget", 0)), epochs=config.rounds,
        local_epochs=settings["local_steps"], learning_rate=settings["learning_rate"], optimizer="SGD",
        momentum=0., weight_decay=0., lr_scheduler=None, batch_size=config.batch_size,
        defense=config.defense, defense_params=defense_params, attack=config.attack, attack_params=attack_params,
        record_time=False, output="unused", distribution=config.distribution, seed=config.seed,
        logger=logging.getLogger("visualfl.flpoison"))


class FlpoisonEngine:
    @staticmethod
    def availability() -> dict:
        missing = [module for module in ["torch"]
                   if importlib.util.find_spec(module) is None]
        reason = "缺少 PyTorch，请运行 visualfl.ps1 setup 安装依赖。" if missing else ""
        return {"id": "flpoison", "name": "内置 PyTorch 引擎", "available": not missing,
                "description": "项目内置客户端、联邦算法和攻防组件 / 自动选择 GPU 或 CPU", "reason": reason,
                "algorithms": ["FedAvg", "FedSGD", "FedOpt"], "source": "VisualFL built-in"}

    def run(self, config: ExperimentConfig, emit: Emit, cancelled: Cancelled) -> None:
        ready = self.availability()
        if not ready["available"]:
            raise RuntimeError(ready["reason"])
        import torch
        from torch.utils.data import TensorDataset, Subset
        from backend.learning.models import get_model
        from backend.learning.attacks import get_attacker_handler
        from backend.learning.client import Client
        from backend.learning.server import Server
        from backend.learning.aggregators.layersift import LayerSiftCancelled

        torch.set_num_threads(1)
        torch.manual_seed(config.seed)
        random.seed(config.seed)
        np.random.seed(config.seed)
        data = prepare_data(config)
        effective = config.resolve_clients()
        emit("data_prepared", data.describe(effective))
        emit("engine_ready", {"backend": "flpoison", "source": "VisualFL built-in learning modules",
                              "implementation": "visualfl.learning.v1", "upstream_revision": UPSTREAM_REVISION,
                              "torch_version": torch.__version__, "device": training_device(), "adapter": "visualfl.digits.v2",
                              "update_kind": "model_parameters" if config.algorithm == "FedAvg" else "model_delta",
                              "local_training_unit": "minibatch_step", "aggregation_weighting": "equal",
                              "partition_hash": data.partition_hash, "model": config.model, "pretrained": False})
        metadata = DATASETS[config.dataset]
        shape = (-1, metadata.get('channels',1), *metadata['shape']) if metadata['kind'] == 'image' else (-1, data.train_x.shape[1])
        x_train = torch.as_tensor(data.train_x.reshape(shape), dtype=torch.float32)
        y_train = torch.tensor(data.train_y, dtype=torch.int64)
        x_test = torch.as_tensor(data.test_x.reshape(shape), dtype=torch.float32)
        y_test = torch.tensor(data.test_y, dtype=torch.int64)
        test_dataset = TensorDataset(x_test, y_test)
        train_dataset = TensorDataset(x_train, y_train)
        shared_model = get_model(make_args(config)) if config.model != "lr" else None
        clients = []
        for i, settings in enumerate(effective):
            args = make_args(config, settings)
            if shared_model is not None:args.shared_model=shared_model
            subset = Subset(train_dataset, data.partitions[i].tolist())
            client_type = get_attacker_handler(config.attack) if settings["malicious"] and config.attack != "None" else Client
            client = client_type(args, i, subset, test_dataset)
            client.set_algorithm(config.algorithm)
            clients.append(client)
        server = Server(make_args(config), clients, test_dataset, train_dataset)
        server.set_algorithm(config.algorithm)
        sampling = np.random.default_rng(config.seed + 101)
        for current in range(1, config.rounds + 1):
            if cancelled():
                return
            started = time.perf_counter()
            selected = sorted(sampling.choice(config.client_count, config.participants, replace=False).tolist())
            emit("round_started", {"round": current, "client_ids": [effective[i]["id"] for i in selected]})
            active_count = 0
            for i in selected:
                if cancelled():
                    return
                client, settings = clients[i], effective[i]
                emit("client_started", {"round": current, "client_id": settings["id"]})
                active = settings["malicious"] and config.attack != "None" and current >= config.attack_start and (
                    config.attack_end is None or current <= config.attack_end)
                active_count += int(active)
                seed = config.seed + current * 1000 + i
                torch.manual_seed(seed)
                random.seed(seed)
                np.random.seed(seed % (2**32))
                client.global_epoch = current - 1
                if settings["malicious"] and config.attack == "BadNets":
                    client.train_loader = client.get_dataloader(client.train_dataset, True,
                                                               poison_epochs=[current - 1] if active else [])
                client.load_global_model(server.global_weights_vec)
                local_start = time.perf_counter()
                train_acc, train_loss = client.local_training()
                client.fetch_updates(benign_flag=not active)
                emit("client_completed", {"round": current, "client_id": settings["id"],
                                          "samples": len(data.partitions[i]), "learning_rate": settings["learning_rate"],
                                          "local_steps": settings["local_steps"], "train_accuracy": float(train_acc),
                                          "native_train_loss": float(train_loss), "attack_active": bool(active),
                                          "update_norm": float(np.linalg.norm(client.update)),
                                          "duration_ms": (time.perf_counter() - local_start) * 1000})
            if cancelled():
                return
            server.clients = [clients[i] for i in selected]
            server.collect_updates(current - 1)
            emit("aggregation_started", {"round": current, "method": config.defense})
            try:
                server.aggregation(cancelled=cancelled)
            except LayerSiftCancelled:
                return
            server.update_global()
            diagnostics = getattr(server.aggregator, 'last_diagnostics', {})
            client_stats = diagnostics.get('clients', [{} for _ in selected])
            payload = {"round": current, "method": config.defense,
                       "clients": [{"client_id": effective[i]["id"],
                                    "update_norm": float(np.linalg.norm(clients[i].update)),
                                    **stats} for i, stats in zip(selected, client_stats)]}
            if diagnostics:
                payload['layersift'] = {key: value for key, value in diagnostics.items() if key != 'clients'}
            emit("aggregation_completed", payload)
            outcome = evaluate_batches(server.global_model,x_test,y_test,min(config.batch_size,64),cancelled)
            if outcome is None:return
            loss,accuracy,_,_=outcome
            metrics = {"round": current, "accuracy": accuracy, "loss": loss, "attack_count": active_count,
                       "participants": len(selected), "source": "measured",
                       "model": config.model, "duration_ms": (time.perf_counter() - started) * 1000}
            groups=[];seen=set()
            for i,settings in enumerate(effective):
                if config.attack != 'BadNets' or not settings['malicious']:continue
                signature=(int(settings['attack_params']['target_label']),int(settings['attack_params']['trigger_size']))
                if signature in seen:continue
                seen.add(signature)
                outcome=evaluate_batches(server.global_model,x_test,y_test,min(config.batch_size,64),cancelled,
                                         clients[i].synthesizer,signature[0])
                if outcome is None:return
                _,_,success,total=outcome
                groups.append({'target':signature[0],'trigger_size':signature[1],'success':success,'total':total,'asr':success/total})
            if groups:
                metrics['asr_groups']=groups
                metrics['asr']=sum(g['success'] for g in groups)/sum(g['total'] for g in groups)
                metrics['asr_definition']='native trigger; excludes original target class; pooled across groups'
            emit('round_completed',metrics)


def evaluate_batches(model,x,y,batch_size,cancelled,synthesizer=None,target_label=None):
    """Bound activation memory and permit cancellation between evaluation batches."""
    import torch
    model.eval()
    parameter = next(model.parameters(), None)
    device = parameter.device if parameter is not None else x.device
    loss=0.;correct=0;total=0
    with torch.inference_mode():
        for offset in range(0,len(y),batch_size):
            if cancelled():return None
            bx,by=x[offset:offset+batch_size],y[offset:offset+batch_size]
            if synthesizer is not None:
                eligible=by != target_label
                bx,by=bx[eligible],by[eligible]
                if not len(by):continue
                bx,by=synthesizer.backdoor_batch(bx.clone(),by.clone(),train=False)
            bx,by=bx.to(device),by.to(device)
            logits=model(bx)
            loss+=float(torch.nn.functional.cross_entropy(logits,by,reduction='sum'))
            correct+=int((logits.argmax(1)==by).sum())
            total+=len(by)
    return loss/total,correct/total,correct,total
