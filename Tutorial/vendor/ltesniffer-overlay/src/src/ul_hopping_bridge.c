#include "srsran/srsran.h"

int ltesniffer_pusch_hopping_init(srsran_ra_ul_pusch_hopping_t* q, srsran_cell_t cell)
{
  return srsran_ra_ul_pusch_hopping_init(q, cell);
}

void ltesniffer_pusch_hopping_free(srsran_ra_ul_pusch_hopping_t* q)
{
  srsran_ra_ul_pusch_hopping_free(q);
}

void ltesniffer_pusch_hopping(srsran_ra_ul_pusch_hopping_t* q,
                              srsran_ul_sf_cfg_t* sf,
                              srsran_pusch_hopping_cfg_t* cfg,
                              srsran_pusch_grant_t* grant)
{
  srsran_ra_ul_pusch_hopping(q, sf, cfg, grant);
}
