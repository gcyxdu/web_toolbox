# SPDX-License-Identifier: GPL-2.0-only
# Derived from FLPoison/fl/server.py; see backend/learning/NOTICE.md and LICENSE.
# Modified 2026-10-29: Local imports; platform owns timing; CPU loaders do not pin memory.

import numpy as np
from backend.learning.aggregators import get_aggregator
from backend.learning.algorithms import get_algorithm_handler
from backend.learning.models import get_model
from backend.learning.models.model_utils import model2vec
from backend.learning.worker import Worker


class Server(Worker):
    def __init__(self, args, clients, test_dataset, train_dataset):
        server_id = -1  # server worker_id = -1
        super().__init__(args, worker_id=server_id)
        self.clients = clients
        self.test_dataset = test_dataset
        self.train_dataset = train_dataset  # it's only used in the defense FLTrust

        # initialize the global model and flattened-model
        self.global_model = get_model(args)
        self.global_weights_vec = model2vec(
            self.global_model)

        self.aggregated_update = np.zeros_like(
            self.global_weights_vec, dtype=np.float32)

        # initialize the aggregator for the server
        self.aggregator = get_aggregator(
            self.args.defense)(self.args, train_dataset=self.train_dataset)

    def set_algorithm(self, algorithm):
        self.algorithm = get_algorithm_handler(
            algorithm)(self.args, self.global_model)

    def collect_updates(self, global_epoch):
        self.global_epoch = global_epoch
        # get the client update from clients
        self.client_updates = np.array(
            [client.update for client in self.clients])

    def aggregation(self, **kwargs):
        # aggregate gradient (for fedsgd), model parameters (for fedavg), and return the aggregated model parameters
        self.aggregated_update = self.aggregator.aggregate(
            self.client_updates, last_global_model=self.global_model, global_weights_vec=self.global_weights_vec, global_epoch=self.global_epoch, **kwargs)

    def update_global(self):
        # update the global model with the aggregated update w.r.t the algorithm
        self.global_weights_vec = self.algorithm.update(
            self.aggregated_update, global_weights_vec=self.global_weights_vec)
