"""
evaluar_netflow_csv.py (Corregido)

Clasifica flujos exportados por CICFlowMeter.
No recibe PCAP directamente: recibe el CSV de características.
"""

import os
# --- Rutas del proyecto (no tocar): el script funciona desde cualquier carpeta ---
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATOS = os.path.join(RAIZ, "datos")
MODELOS = os.path.join(RAIZ, "modelos")
RESULTADOS = os.path.join(RAIZ, "resultados")
for _c in (DATOS, MODELOS, RESULTADOS):
    os.makedirs(_c, exist_ok=True)
import argparse
import joblib
import numpy as np
import pandas as pd

MODEL_PATH = os.path.join(MODELOS, "modelo_netflow_combinado_xgb.pkl")


def get_features(model, stored_columns=None):
    if stored_columns is not None:
        return list(stored_columns)

    names = getattr(model, "feature_names_in_", None)

    if names is not None:
        return list(names)

    if hasattr(model, "get_booster"):
        names = model.get_booster().feature_names
        if names:
            return list(names)

    raise ValueError(
        "No se pudo recuperar el esquema del modelo. "
        "Carga la lista exacta de features usada en el entrenamiento."
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True)
    parser.add_argument("--threshold", type=float, default=0.80)
    parser.add_argument("--class-name", default="Botnet")
    parser.add_argument("--out", default=os.path.join(RESULTADOS, "predicciones_netflow.csv"))
    args = parser.parse_args()

    if not 0 <= args.threshold <= 1:
        parser.error("--threshold debe estar entre 0 y 1")

    # Cargar el archivo .pkl (que almacena un diccionario con el modelo, columnas y clases)
    loaded_data = joblib.load(MODEL_PATH)

    if isinstance(loaded_data, dict):
        model = loaded_data["modelo"]
        stored_columns = loaded_data.get("columnas", None)
    else:
        model = loaded_data
        stored_columns = None

    if not hasattr(model, "predict_proba"):
        raise TypeError("El objeto cargado no es un modelo válido con predict_proba.")

    df = pd.read_csv(args.csv, low_memory=False)
    df.columns = df.columns.str.strip()

    # Algunas exportaciones contienen filas sin datos útiles.
    df = df.dropna(how="all").reset_index(drop=True)

    features = get_features(model, stored_columns)

    # No inventar valores para features ausentes.
    missing = [f for f in features if f not in df.columns]
    if missing:
        raise ValueError(
            "El CSV no coincide con el esquema del modelo.\n"
            f"Columnas ausentes ({len(missing)}): {missing}\n"
            "Revisa la versión de CICFlowMeter y el mapeo."
        )

    X = df.loc[:, features].copy()

    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    values = X.to_numpy(dtype=float)

    if not np.isfinite(values).all():
        bad = X.columns[
            ~np.isfinite(values).all(axis=0)
        ].tolist()
        raise ValueError(
            f"Hay valores ausentes o infinitos en: {bad}. "
            "Aplica el mismo tratamiento del entrenamiento."
        )

    probabilities = model.predict_proba(X)
    classes = list(model.classes_)

    target_matches = [
        i for i, cls in enumerate(classes)
        if str(cls).casefold() == args.class_name.casefold()
    ]

    if len(target_matches) != 1:
        raise ValueError(
            f"Clase {args.class_name!r} no encontrada. "
            f"Clases disponibles: {classes}"
        )

    target_idx = target_matches[0]
    other_idx = [i for i in range(len(classes)) if i != target_idx]

    if not other_idx:
        raise ValueError("El modelo solo contiene una clase.")

    target_prob = probabilities[:, target_idx]
    other_prob = probabilities[:, other_idx]

    other_classes = np.array(classes, dtype=object)[other_idx]
    best_other = other_classes[np.argmax(other_prob, axis=1)]

    # Política de decisión con el umbral (threshold) estricto configurado.
    predictions = np.where(
        target_prob >= args.threshold,
        classes[target_idx],
        best_other,
    )

    output = pd.DataFrame({
        "prediccion": predictions,
        f"prob_{args.class_name}": target_prob,
        "umbral": args.threshold,
    })

    for i, cls in enumerate(classes):
        output[f"prob_{cls}"] = probabilities[:, i]

    output.to_csv(args.out, index=False)

    print(f"Flujos evaluados: {len(X)}")
    print(f"Clase objetivo: {args.class_name}")
    print(f"Umbral aplicado: {args.threshold:.2f}")
    print("\nDistribución de predicciones:")
    print(output["prediccion"].value_counts().to_string())
    print(f"\nArchivo generado: {args.out}")


if __name__ == "__main__":
    main()