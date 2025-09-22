import { t } from "../i18n";
import { PRIMARY_ITEMS } from "../menu";
import type { PrimaryKey } from "../types";

type Props = {
  activePrimary: PrimaryKey;
  onPrimaryClick: (p: PrimaryKey) => void;
  onPrimaryHover: (p: PrimaryKey) => void;
};

export default function PrimaryNav({ activePrimary, onPrimaryClick, onPrimaryHover }: Props) {
  const topItems = PRIMARY_ITEMS.filter(i => i.showInPrimary);
  const accountItem = PRIMARY_ITEMS.find(i => i.key === "account")!;

  return (
    <>
      <nav className="nav primary" aria-label="Primary navigation (desktop)">
        <p className="primary-title">Primary</p>

        <div className="primary-list">
          {topItems.map(item => (
            <button
              key={item.key}
              className={"iconbtn " + (activePrimary === item.key ? "active" : "")}
              title={t(item.label)}
              onClick={() => onPrimaryClick(item.key)}
              onMouseEnter={() => onPrimaryHover(item.key)}
              onFocus={() => onPrimaryHover(item.key)}
            >
              <span aria-hidden>{item.icon}</span>
            </button>
          ))}
        </div>

        <div className="primary-spacer" />

        <div className="primary-account">
          <button
            className={"iconbtn " + (activePrimary === "account" ? "active" : "")}
            title={t(accountItem.label)}
            onClick={() => onPrimaryClick("account")}
          >
            <span aria-hidden>{accountItem.icon}</span>
          </button>
        </div>
      </nav>

      <div className="primary-bottom" aria-label="Primary navigation (mobile)">
        {topItems.map(item => (
          <button
            key={item.key}
            className={"iconbtn " + (activePrimary === item.key ? "active" : "")}
            title={t(item.label)}
            onClick={() => onPrimaryClick(item.key)}
          >
            <span aria-hidden>{item.icon}</span>
          </button>
        ))}

        <button
          className={"iconbtn " + (activePrimary === "account" ? "active" : "")}
          title={t(accountItem.label)}
          onClick={() => onPrimaryClick("account")}
        >
          <span aria-hidden>{accountItem.icon}</span>
        </button>
      </div>
    </>
  );
}
