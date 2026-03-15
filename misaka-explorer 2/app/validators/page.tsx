import { api } from '@/lib/api/client';
import { ValidatorTable } from '@/components/explorer/ValidatorTable';

export const revalidate = 30;

export default async function ValidatorsPage() {
  const res = await api.getValidatorList(1, 50);

  return (
    <div className="page-enter space-y-6">
      <div>
        <h1 className="font-display text-2xl font-bold text-white tracking-tight">Validators</h1>
        <p className="text-sm text-slate-500 mt-1">
          Active validator set for the MISAKA network ({res.total} total)
        </p>
      </div>

      <div className="rounded-xl border border-surface-300/50 bg-surface-100 overflow-hidden">
        <ValidatorTable validators={res.data} />
      </div>
    </div>
  );
}
