import { t } from "../i18n";
import { PRIMARY_ITEMS } from "../menu";
import type { PrimaryKey, SecondaryItem, SecondaryKey } from "../types";

type Props = {
  secondaryPrimary: PrimaryKey;            
  activePrimary: PrimaryKey;               
  items: SecondaryItem[];                   
  activeSecondary: SecondaryKey;            
  onSecondaryClick: (s: SecondaryKey) => void;
};

export default function SecondaryNav({
  secondaryPrimary, activePrimary, items, activeSecondary, onSecondaryClick
}: Props) {
  const title = PRIMARY_ITEMS.find(i => i.key === secondaryPrimary)!.label;
  return (
    <nav className="nav secondary" aria-label="Secondary navigation">
      <h3>{t(title)}</h3>
      <ul className="secondary-list">
        {items.map(it => (
          <li key={it.key}>
            <button
              className={
                "itembtn " +
                (activeSecondary === it.key && activePrimary === secondaryPrimary ? "active" : "")
              }
              onClick={() => onSecondaryClick(it.key)}
            >
              {t(it.label)}
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}
