#!/bin/bash

(cd ./server && gnome-terminal --title="server" -- bash -c "./server iris 15 3 0.2; exec bash")

gnome-terminal --title="client1" -- bash -c "./app ./dataset/IrisData/iris_train_part_1.txt iris; exec bash"

gnome-terminal --title="client2" -- bash -c "./app ./dataset/IrisData/iris_train_part_2.txt iris; exec bash"
