import { type ReactNode } from "react";
type ColorType =
  | "primary"
  | "secondary"
  | "success"
  | "danger"
  | "warning"
  | "info"
  | "light"
  | "dark";
interface ButtonProps {
  children: ReactNode;
  color?: ColorType;
  onClick: () => void;
}
const button = ({ children, onClick, color = "primary" }: ButtonProps) => {
  return (
    <button className={"btn btn-" + color} onClick={onClick}>
      {children}
    </button>
  );
};

export default button;
