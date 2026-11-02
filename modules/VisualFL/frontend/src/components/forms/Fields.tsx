import { useId, useEffect, useState } from 'react';
import { Select, TextField } from '@radix-ui/themes';
import type { Method } from '../../types';

interface NumberProps {
  label: string;
  value: number | null;
  onChange: (value: number) => void;
  min?: number;
  max?: number;
  step?: number;
  hint?: string;
  disabled?: boolean;
  placeholder?: string;
}
export function NumberField({
  label,
  value,
  onChange,
  min,
  max,
  step = 1,
  hint,
  disabled,
  placeholder,
}: NumberProps) {
  const id = useId();
  const [text, setText] = useState(value == null ? '' : String(value));
  useEffect(() => setText(value == null ? '' : String(value)), [value]);
  const valid = (next: string) =>
    next.trim() !== '' &&
    Number.isFinite(Number(next)) &&
    (min === undefined || Number(next) >= min) &&
    (max === undefined || Number(next) <= max) &&
    (step !== 1 || Number.isInteger(Number(next)));
  function commit() {
    if (valid(text)) onChange(Number(text));
    else setText(value == null ? '' : String(value));
  }
  return (
    <div className="field">
      <label htmlFor={id} title={hint}>
        {label}
      </label>
      <TextField.Root
        id={id}
        type="number"
        value={text}
        placeholder={placeholder}
        min={min}
        max={max}
        step={step}
        disabled={disabled}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            e.currentTarget.blur();
          }
        }}
        onChange={(e) => {
          setText(e.target.value);
        }}
      />
    </div>
  );
}

interface SelectProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string; disabled?: boolean }[];
  disabled?: boolean;
  hint?: string;
}
export function SelectField({ label, value, onChange, options, disabled, hint }: SelectProps) {
  return (
    <div className="field">
      <label>{label}</label>
      <Select.Root value={value} onValueChange={onChange} disabled={disabled}>
        <Select.Trigger aria-label={label} />
        <Select.Content position="popper">
          {options.map((option) => (
            <Select.Item key={option.value} value={option.value} disabled={option.disabled}>
              {option.label}
            </Select.Item>
          ))}
        </Select.Content>
      </Select.Root>
    </div>
  );
}

export function MethodFields({
  method,
  values,
  onChange,
  disabled,
  inherited,
  classes = 10,
}: {
  method?: Method;
  values: Record<string, number>;
  onChange: (key: string, value: number) => void;
  disabled?: boolean;
  inherited?: Record<string, number>;
  classes?: number;
}) {
  if (!method || !method.fields.length) return null;
  return (
    <div className="field-grid">
      {method.fields.map((field) => (
        <NumberField
          key={field.key}
          label={field.label}
          value={values[field.key] ?? inherited?.[field.key] ?? field.default}
          min={field.min}
          max={field.key === 'target_label' ? classes - 1 : field.max}
          step={field.step}
          onChange={(value) => onChange(field.key, value)}
          disabled={disabled}
          hint={
            values[field.key] !== undefined
              ? '当前配置'
              : inherited?.[field.key] !== undefined
                ? '继承场景配置'
                : '方法默认值'
          }
        />
      ))}
    </div>
  );
}
