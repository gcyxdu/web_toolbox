#!/bin/bash

(cd ./server && gnome-terminal --title="server" -- bash -c "./server bank; exec bash")

gnome-terminal --title="client1" -- bash -c "./app ./dataset/bankData/bank_train_part_1.txt bank; exec bash"

gnome-terminal --title="client2" -- bash -c "./app ./dataset/bankData/bank_train_part_2.txt bank; exec bash"

gnome-terminal --title="client3" -- bash -c "./app ./dataset/bankData/bank_train_part_3.txt bank; exec bash"
