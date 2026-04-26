import torch
import torch.nn as nn
import numpy as np

DEVICE = torch.device("cpu") #Use CPU only for Lower latency.


# ===============================
# MODEL DEFINITIONS
# ===============================

class ResidualMLP_1024(nn.Module):
    def __init__(self, input_dim=37):
        super().__init__()

        self.fc1 = nn.Linear(input_dim, 1024)
        self.bn1 = nn.BatchNorm1d(1024)
        self.drop1 = nn.Dropout(0.15)

        self.fc2 = nn.Linear(1024, 1024)
        self.bn2 = nn.BatchNorm1d(1024)
        self.drop2 = nn.Dropout(0.15)

        self.fc3 = nn.Linear(1024, 512)
        self.bn3 = nn.BatchNorm1d(512)

        self.fc4 = nn.Linear(512, 256)
        self.bn4 = nn.BatchNorm1d(256)

        self.fc5 = nn.Linear(256, 128)
        self.bn5 = nn.BatchNorm1d(128)

        self.out = nn.Linear(128, 2)
        self.act = nn.GELU()

    def forward(self, x):
        x1 = self.act(self.bn1(self.fc1(x)))
        x1 = self.drop1(x1)

        x2 = self.act(self.bn2(self.fc2(x1)))
        x2 = x2 + x1
        x2 = self.drop2(x2)

        x3 = self.act(self.bn3(self.fc3(x2)))
        x4 = self.act(self.bn4(self.fc4(x3)))
        x5 = self.act(self.bn5(self.fc5(x4)))

        return self.out(x5)


class ResidualMLP_768(nn.Module):
    def __init__(self, input_dim=37):
        super().__init__()

        self.fc1 = nn.Linear(input_dim, 768)
        self.bn1 = nn.BatchNorm1d(768)
        self.drop1 = nn.Dropout(0.15)

        self.fc2 = nn.Linear(768, 768)
        self.bn2 = nn.BatchNorm1d(768)
        self.drop2 = nn.Dropout(0.15)

        self.fc3 = nn.Linear(768, 512)
        self.bn3 = nn.BatchNorm1d(512)

        self.fc4 = nn.Linear(512, 256)
        self.bn4 = nn.BatchNorm1d(256)

        self.fc5 = nn.Linear(256, 128)
        self.bn5 = nn.BatchNorm1d(128)

        self.out = nn.Linear(128, 6)
        self.act = nn.GELU()

    def forward(self, x):
        x1 = self.act(self.bn1(self.fc1(x)))
        x1 = self.drop1(x1)

        x2 = self.act(self.bn2(self.fc2(x1)))
        x2 = x2 + x1
        x2 = self.drop2(x2)

        x3 = self.act(self.bn3(self.fc3(x2)))
        x4 = self.act(self.bn4(self.fc4(x3)))
        x5 = self.act(self.bn5(self.fc5(x4)))

        return self.out(x5)


# ===============================
# LOAD MODELS
# ===============================

binary_model = ResidualMLP_1024().to(DEVICE)
binary_model.load_state_dict(torch.load(
    "models/IDS-MLP-6_class_Binary-epoch8-F1_0.9969.pth",
    map_location=DEVICE,
    weights_only=True
))
binary_model.eval()


six_model = ResidualMLP_768().to(DEVICE)
six_model.load_state_dict(torch.load(
    "models/IDS-MLP-6class-epoch10-F1_0.9874.pth",
    map_location=DEVICE,
    weights_only=True
))
six_model.eval()


# ===============================
# PREDICTION FUNCTION
# ===============================

def predict(features: np.ndarray):
    """
    features shape:
        (37,)      -> single sample
        (N, 37)    -> batch
    returns:
        predicted labels
        0 = normal
        1-6 = attack types
    """

    if features.ndim == 1:
        features = features.reshape(1, -1)

    x = torch.tensor(features, dtype=torch.float32).to(DEVICE)

    with torch.no_grad():

        # ---- Binary stage ----
        logits = binary_model(x)
        binary_pred = torch.argmax(logits, dim=1)

        final_pred = binary_pred.clone()

        # ---- Second stage ----
        attack_mask = binary_pred == 1

        if attack_mask.sum() > 0:

            attack_samples = x[attack_mask]

            logits = six_model(attack_samples)
            six_pred = torch.argmax(logits, dim=1) + 1

            final_pred[attack_mask] = six_pred

    return final_pred.cpu().numpy()