import { api } from '@/lib/api/client';
import { ValidatorTable } from '@/components/explorer/ValidatorTable';

export const revalidate = 30;

export default async function ValidatorsPage() {
  const res = await api.getValidatorList(1, 50);

  return (
    <div className="page-enter space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-fg tracking-tight">Validators</h1>
        <p className="text-sm text-muted mt-1">
          Active validator set for the MISAKA network ({res.total} total)
        </p>
      </div>

      <div className="rounded-none border border-line bg-surface overflow-hidden">
        <ValidatorTable validators={res.data} />
      </div>
    </div>
  );
}
